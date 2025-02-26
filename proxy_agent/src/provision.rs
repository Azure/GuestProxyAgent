// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module provides the provision functions for the GPA service and GPA --status command line.
//! It is used to track the provision state for each module and write the provision state to provisioned.tag and status.tag files.
//! It also provides the http handler to query the provision status for GPA service.
//! It is used to query the provision status from GPA service http listener.
//! Example for GPA service:
//! ```rust
//! use proxy_agent::provision;
//! use proxy_agent::shared_state::agent_status_wrapper::AgentStatusModule;
//! use proxy_agent::shared_state::agent_status_wrapper::AgentStatusSharedState;
//! use proxy_agent::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
//! use proxy_agent::shared_state::provision_wrapper::ProvisionSharedState;
//! use proxy_agent::shared_state::SharedState;
//! use proxy_agent::shared_state::telemetry_wrapper::TelemetrySharedState;
//!
//! use std::time::Duration;
//!
//! let shared_state = SharedState::start_all();
//! let cancellation_token = shared_state.get_cancellation_token();
//! let key_keeper_shared_state = shared_state.get_key_keeper_shared_state();
//! let telemetry_shared_state = shared_state.get_telemetry_shared_state();
//! let provision_shared_state = shared_state.get_provision_shared_state();
//! let agent_status_shared_state = shared_state.get_agent_status_shared_state();
//!
//! let provision_state = provision::get_provision_state(
//!     provision_shared_state.clone(),
//!     agent_status_shared_state.clone(),
//! ).await;
//! assert_eq!(false, provision_state.finished);
//! assert_eq!(0, provision_state.errorMessage.len());
//!
//! // update provision state when each provision finished
//! provision::redirector_ready(
//!     cancellation_token.clone(),
//!     key_keeper_shared_state.clone(),
//!     telemetry_shared_state.clone(),
//!     provision_shared_state.clone(),
//!     agent_status_shared_state.clone(),
//! ).await;
//! provision::key_latched(
//!     cancellation_token.clone(),
//!     key_keeper_shared_state.clone(),
//!     telemetry_shared_state.clone(),
//!     provision_shared_state.clone(),
//!     agent_status_shared_state.clone(),
//! ).await;
//! provision::listener_started(
//!     cancellation_token.clone(),
//!     key_keeper_shared_state.clone(),
//!     telemetry_shared_state.clone(),
//!     provision_shared_state.clone(),
//!     agent_status_shared_state.clone(),
//! ).await;
//!
//! let provision_state = provision::get_provision_state(
//!     provision_shared_state.clone(),
//!     agent_status_shared_state.clone(),
//! ).await;
//! assert_eq!(true, provision_state.finished);
//! assert_eq!(0, provision_state.errorMessage.len());
//! ```
//!
//! Example for GPA command line option --status [--wait seconds]:
//! ```rust
//! use proxy_agent::provision::ProvisionQuery;
//! use std::time::Duration;
//!
//! let proxy_server_port = 8092;
//! let provision_query = ProvisionQuery::new(proxy_server_port, None);
//! let provision_not_finished_state = provision_query.get_provision_status_wait().await;
//! assert_eq!(false, provision_state.0);
//! assert_eq!(0, provision_state.1.len());
//!
//! let provision_query = ProvisionQuery::new(proxy_server_port, Some(Duration::from_millis(5)));
//! let provision_finished_state = provision_query.get_provision_status_wait().await;
//! assert_eq!(true, provision_state.0);
//! assert_eq!(0, provision_state.1.len());
//! ```

use crate::common::{
    config, constants, error::Error, helpers, hyper_client, logger, result::Result,
};
use crate::proxy_agent_status;
use crate::shared_state::agent_status_wrapper::{AgentStatusModule, AgentStatusSharedState};
use crate::shared_state::key_keeper_wrapper::KeyKeeperSharedState;
use crate::shared_state::provision_wrapper::ProvisionSharedState;
use crate::shared_state::telemetry_wrapper::TelemetrySharedState;
use crate::telemetry::event_reader::EventReader;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const STATUS_TAG_TMP_FILE_NAME: &str = "status.tag.tmp";
const STATUS_TAG_FILE_NAME: &str = "status.tag";

bitflags::bitflags! {
    /// Provision flags
    /// NONE - no provision finished
    /// REDIRECTOR_READY - redirector provision finished
    /// KEY_LATCH_READY - key latch provision finished
    /// LISTENER_READY - listener provision finished
    /// ALL_READY - all provision finished
    /// It is used to track each module provision state
    /// Example:
    /// ```rust
    /// use proxy_agent::provision::ProvisionFlags;
    ///
    /// let flags = ProvisionFlags::REDIRECTOR_READY | ProvisionFlags::KEY_LATCH_READY;
    /// assert_eq!(3, flags.bits());
    /// assert_eq!(true, flags.contains(ProvisionFlags::REDIRECTOR_READY));
    /// assert_eq!(true, flags.contains(ProvisionFlags::KEY_LATCH_READY));
    /// assert_eq!(false, flags.contains(ProvisionFlags::LISTENER_READY));
    ///
    /// let flags = ProvisionFlags::REDIRECTOR_READY | ProvisionFlags::KEY_LATCH_READY | ProvisionFlags::LISTENER_READY;
    /// assert_eq!(7, flags.bits());
    /// assert_eq!(true, flags.contains(ProvisionFlags::REDIRECTOR_READY));
    /// assert_eq!(true, flags.contains(ProvisionFlags::KEY_LATCH_READY));
    /// assert_eq!(true, flags.contains(ProvisionFlags::LISTENER_READY));
    /// ```
    #[derive(Clone, Debug)]
    pub struct ProvisionFlags: u8 {
        const NONE = 0;
        const REDIRECTOR_READY = 1;
        const KEY_LATCH_READY = 2;
        const LISTENER_READY = 4;
        const ALL_READY = 7;
    }
}

/// Provision status
/// finished - provision finished or timedout
///            true means provision finished or timedout, false means provision still in progress
/// errorMessage - provision error message
#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct ProvisionState {
    pub finished: bool,
    pub errorMessage: String,
}

impl ProvisionState {
    pub fn new(finished: bool, error_message: String) -> Self {
        ProvisionState {
            finished,
            errorMessage: error_message,
        }
    }
}

/// Provision URL path, it is used to query the provision status from GPA service http listener
pub const PROVISION_URL_PATH: &str = "/provision";

/// Update provision state when redirector provision finished
/// It could  be called by redirector module
pub async fn redirector_ready(
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    telemetry_shared_state: TelemetrySharedState,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    update_provision_state(
        ProvisionFlags::REDIRECTOR_READY,
        None,
        cancellation_token,
        key_keeper_shared_state,
        telemetry_shared_state,
        provision_shared_state,
        agent_status_shared_state,
    )
    .await;
}

/// Update provision state when key latch provision finished
/// It could  be called by key latch module
pub async fn key_latched(
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    telemetry_shared_state: TelemetrySharedState,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    update_provision_state(
        ProvisionFlags::KEY_LATCH_READY,
        None,
        cancellation_token,
        key_keeper_shared_state,
        telemetry_shared_state,
        provision_shared_state,
        agent_status_shared_state,
    )
    .await;
}

/// Update provision state when listener provision finished
/// It could  be called by listener module
pub async fn listener_started(
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    telemetry_shared_state: TelemetrySharedState,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    update_provision_state(
        ProvisionFlags::LISTENER_READY,
        None,
        cancellation_token,
        key_keeper_shared_state,
        telemetry_shared_state,
        provision_shared_state,
        agent_status_shared_state,
    )
    .await;
}

/// Update provision state for each module to shared_state
async fn update_provision_state(
    state: ProvisionFlags,
    provision_dir: Option<PathBuf>,
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    telemetry_shared_state: TelemetrySharedState,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    if let Ok(provision_state) = provision_shared_state.update_one_state(state).await {
        if provision_state.contains(ProvisionFlags::ALL_READY) {
            if let Err(e) = provision_shared_state.set_provision_finished(true).await {
                // log the error and continue
                logger::write_error(format!(
                    "update_provision_state::Failed to set provision finished with error: {e}"
                ));
            }

            // write provision success state here
            write_provision_state(
                provision_dir,
                provision_shared_state.clone(),
                agent_status_shared_state.clone(),
            )
            .await;

            // start event threads right after provision successfully
            start_event_threads(
                cancellation_token,
                key_keeper_shared_state,
                telemetry_shared_state,
                provision_shared_state,
                agent_status_shared_state,
            )
            .await;
        }
    }
}

pub async fn key_latch_ready_state_reset(provision_shared_state: ProvisionSharedState) {
    reset_provision_state(ProvisionFlags::KEY_LATCH_READY, provision_shared_state).await;
}

async fn reset_provision_state(
    state_to_reset: ProvisionFlags,
    provision_shared_state: ProvisionSharedState,
) {
    let provision_state = match provision_shared_state.reset_one_state(state_to_reset).await {
        Ok(state) => state,
        Err(e) => {
            logger::write_error(format!("Failed to reset provision state with error: {e}"));
            return;
        }
    };
    if let Err(e) = provision_shared_state
        .set_provision_finished(provision_state.contains(ProvisionFlags::ALL_READY))
        .await
    {
        logger::write_error(format!(
            "reset_provision_state::Failed to set provision finished with error: {e}"
        ));
    }
}

/// Update provision state when provision timedout
/// It will be called if key latch provision timedout
/// Example:
/// ```rust
/// use proxy_agent::provision;
/// use std::sync::{Arc, Mutex};
///
/// let shared_state = Arc::new(Mutex::new(SharedState::new()));
/// provision::provision_timeup(None, shared_state.clone());
/// ```
pub async fn provision_timeup(
    provision_dir: Option<PathBuf>,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    let provision_state = provision_shared_state
        .get_state()
        .await
        .unwrap_or(ProvisionFlags::NONE);
    if !provision_state.contains(ProvisionFlags::ALL_READY) {
        if let Err(e) = provision_shared_state.set_provision_finished(true).await {
            logger::write_error(format!("Failed to set provision finished with error: {e}"));
        }

        // write provision state
        write_provision_state(
            provision_dir,
            provision_shared_state,
            agent_status_shared_state,
        )
        .await;
    }
}

/// Start event logger & reader tasks and status reporting task
/// It will be called when provision finished or timedout,
/// it is designed to delay start those tasks to give more cpu time to provision tasks
pub async fn start_event_threads(
    cancellation_token: CancellationToken,
    key_keeper_shared_state: KeyKeeperSharedState,
    telemetry_shared_state: TelemetrySharedState,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    if let Ok(logger_threads_initialized) = provision_shared_state
        .get_event_log_threads_initialized()
        .await
    {
        if logger_threads_initialized {
            return;
        }
    }

    let cloned_agent_status_shared_state = agent_status_shared_state.clone();
    tokio::spawn({
        async {
            event_logger::start(
                config::get_events_dir(),
                Duration::default(),
                config::get_max_event_file_count(),
                move |status: String| {
                    let cloned_agent_status_shared_state = cloned_agent_status_shared_state.clone();
                    async move {
                        let _ = cloned_agent_status_shared_state
                            .set_module_status_message(status, AgentStatusModule::TelemetryLogger)
                            .await;
                    }
                },
            )
            .await;
        }
    });
    tokio::spawn({
        let event_reader = EventReader::new(
            config::get_events_dir(),
            true,
            cancellation_token.clone(),
            key_keeper_shared_state.clone(),
            telemetry_shared_state.clone(),
            agent_status_shared_state.clone(),
        );
        async move {
            event_reader
                .start(Some(Duration::from_secs(300)), None, None)
                .await;
        }
    });
    if let Err(e) = provision_shared_state
        .set_event_log_threads_initialized()
        .await
    {
        logger::write_warning(format!(
            "Failed to set event log threads initialized with error: {e}"
        ));
    }

    tokio::spawn({
        let agent_status_task = proxy_agent_status::ProxyAgentStatusTask::new(
            Duration::from_secs(60),
            config::get_logs_dir(),
            cancellation_token.clone(),
            key_keeper_shared_state.clone(),
            agent_status_shared_state.clone(),
        );
        async move {
            agent_status_task.start().await;
        }
    });
}

/// Write provision state to provisioned.tag file and status.tag file under provision_dir
/// provisioned.tag is backcompat file, it is used to indicate the provision finished for pilot WinPA
/// status.tag is used to store the provision error message for current WinPA service to query the provision status
///  if status.tag file exists, it means provision finished
///  if status.tag file does not exist, it means provision still in progress
///  the content of the status.tag file is the provision error message,
///  empty means provision success, otherwise provision failed with error message
async fn write_provision_state(
    provision_dir: Option<PathBuf>,
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) {
    let provision_dir = provision_dir.unwrap_or_else(config::get_keys_dir);
    let provisioned_file: PathBuf = provision_dir.join("provisioned.tag");
    if let Err(e) = misc_helpers::try_create_folder(&provision_dir) {
        logger::write_error(format!("Failed to create provision folder with error: {e}"));
        return;
    }

    if let Err(e) = std::fs::write(
        provisioned_file,
        misc_helpers::get_date_time_string_with_milliseconds(),
    ) {
        logger::write_error(format!("Failed to write provisioned file with error: {e}"));
    }

    let failed_state_message =
        get_provision_failed_state_message(provision_shared_state, agent_status_shared_state).await;

    #[cfg(not(windows))]
    {
        if failed_state_message.is_empty() {
            logger::write_serial_console_log("Provision finished successfully".to_string());
        } else {
            logger::write_serial_console_log(failed_state_message.clone());
        }
    }

    let status_file: PathBuf = provision_dir.join(STATUS_TAG_TMP_FILE_NAME);
    match std::fs::write(status_file, failed_state_message.as_bytes()) {
        Ok(_) => {
            match std::fs::rename(
                provision_dir.join(STATUS_TAG_TMP_FILE_NAME),
                provision_dir.join(STATUS_TAG_FILE_NAME),
            ) {
                Ok(_) => {}
                Err(e) => {
                    logger::write_error(format!("Failed to rename status file with error: {e}"));
                }
            }
        }
        Err(e) => {
            logger::write_error(format!("Failed to write temp status file with error: {e}"));
        }
    }
}

/// Get provision failed state message
async fn get_provision_failed_state_message(
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) -> String {
    let provision_state = match provision_shared_state.get_state().await {
        Ok(state) => state,
        Err(e) => {
            logger::write_error(format!("Failed to get provision state with error: {e}"));
            ProvisionFlags::NONE
        }
    };

    let mut state = String::new(); //provision success, write 0 byte to file
    if !provision_state.contains(ProvisionFlags::REDIRECTOR_READY) {
        state.push_str(&format!(
            "ebpfProgramStatus - {}\r\n",
            agent_status_shared_state
                .get_module_status(AgentStatusModule::Redirector)
                .await
                .message
        ));
    }

    if !provision_state.contains(ProvisionFlags::KEY_LATCH_READY) {
        state.push_str(&format!(
            "keyLatchStatus - {}\r\n",
            agent_status_shared_state
                .get_module_status(AgentStatusModule::KeyKeeper)
                .await
                .message
        ));
    }

    if !provision_state.contains(ProvisionFlags::LISTENER_READY) {
        state.push_str(&format!(
            "proxyListenerStatus - {}\r\n",
            agent_status_shared_state
                .get_module_status(AgentStatusModule::ProxyServer)
                .await
                .message
        ));
    }

    state
}

/// Get provision state
/// It returns the current GPA serice provision state (from shared_state) for GPA service
/// This function is designed and invoked in GPA service
pub async fn get_provision_state(
    provision_shared_state: ProvisionSharedState,
    agent_status_shared_state: AgentStatusSharedState,
) -> ProvisionState {
    ProvisionState {
        finished: provision_shared_state
            .get_provision_finished()
            .await
            .unwrap_or(false),
        errorMessage: get_provision_failed_state_message(
            provision_shared_state,
            agent_status_shared_state,
        )
        .await,
    }
}

/// Provision query
/// It is used to query the provision status from GPA service via http request
/// This struct is designed for GPA command line, serves for --status [--wait seconds] option
pub struct ProvisionQuery {
    port: u16,
    wait_duration: Option<Duration>,
}

impl ProvisionQuery {
    pub fn new(port: u16, wait_duration: Option<Duration>) -> ProvisionQuery {
        ProvisionQuery {
            port,
            wait_duration,
        }
    }

    /// Get current GPA service provision status and wait until the GPA service provision finished or timeout
    /// This function is designed for GPA command line, serves for --status [--wait seconds] option
    pub async fn get_provision_status_wait(&self) -> ProvisionState {
        loop {
            let state = match self.get_current_provision_status().await {
                Ok(state) => state,
                Err(e) => {
                    println!(
                        "Failed to query the current provision state with error: {}.",
                        e
                    );
                    ProvisionState::new(false, String::new())
                }
            };
            if state.finished {
                return state;
            }

            if let Some(d) = self.wait_duration {
                if d.as_millis() >= helpers::get_elapsed_time_in_millisec() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }

            // wait timedout return as 'not finished' with empty message
            return ProvisionState::new(false, String::new());
        }
    }

    // Get current provision status from GPA service via http request
    // return value
    //  bool - true provision finished; false provision not finished
    //  String - provision error message, empty means provision success or provision failed.
    async fn get_current_provision_status(&self) -> Result<ProvisionState> {
        let provision_url: String = format!(
            "http://{}:{}{}",
            Ipv4Addr::LOCALHOST,
            self.port,
            PROVISION_URL_PATH
        );

        let provision_url: hyper::Uri = provision_url
            .parse::<hyper::Uri>()
            .map_err(|e| Error::ParseUrl(provision_url, e.to_string()))?;

        let mut headers = HashMap::new();
        headers.insert(constants::METADATA_HEADER.to_string(), "true".to_string());
        hyper_client::get(&provision_url, &headers, None, None, logger::write_warning).await
    }
}

#[cfg(test)]
mod tests {
    use crate::provision::ProvisionFlags;
    use crate::proxy::proxy_server;
    use crate::shared_state::SharedState;
    use std::env;
    use std::fs;
    use std::time::Duration;

    #[tokio::test]
    async fn provision_state_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "provision_state_test";
        temp_test_path.push(logger_key);

        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);

        // start listener, the port must different from the one used in production code
        let shared_state = SharedState::start_all();
        let cancellation_token = shared_state.get_cancellation_token();
        let provision_shared_state = shared_state.get_provision_shared_state();
        let key_keeper_shared_state = shared_state.get_key_keeper_shared_state();
        let telemetry_shared_state = shared_state.get_telemetry_shared_state();
        let agent_status_shared_state = shared_state.get_agent_status_shared_state();
        let port: u16 = 8092;
        let proxy_server = proxy_server::ProxyServer::new(port, &shared_state);

        tokio::spawn({
            let proxy_server = proxy_server.clone();
            async move {
                proxy_server.start().await;
            }
        });

        // give some time to let the listener started
        let sleep_duration = Duration::from_millis(100);
        tokio::time::sleep(sleep_duration).await;

        let provision_query = super::ProvisionQuery::new(port, None);
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(
            !provision_status.finished,
            "provision_status.0 must be false"
        );
        assert_eq!(
            0,
            provision_status.errorMessage.len(),
            "provision_status.1 must be empty"
        );

        let dir1 = temp_test_path.to_path_buf();
        let dir2 = temp_test_path.to_path_buf();
        let dir3 = temp_test_path.to_path_buf();

        let handles = vec![
            super::update_provision_state(
                ProvisionFlags::REDIRECTOR_READY,
                Some(dir1),
                cancellation_token.clone(),
                key_keeper_shared_state.clone(),
                telemetry_shared_state.clone(),
                provision_shared_state.clone(),
                agent_status_shared_state.clone(),
            ),
            super::update_provision_state(
                ProvisionFlags::KEY_LATCH_READY,
                Some(dir2),
                cancellation_token.clone(),
                key_keeper_shared_state.clone(),
                telemetry_shared_state.clone(),
                provision_shared_state.clone(),
                agent_status_shared_state.clone(),
            ),
            super::update_provision_state(
                ProvisionFlags::LISTENER_READY,
                Some(dir3),
                cancellation_token.clone(),
                key_keeper_shared_state.clone(),
                telemetry_shared_state.clone(),
                provision_shared_state.clone(),
                agent_status_shared_state.clone(),
            ),
        ];
        for handle in handles {
            handle.await;
        }

        let provisioned_file = temp_test_path.join("provisioned.tag");
        assert!(provisioned_file.exists());

        let status_file = temp_test_path.join(super::STATUS_TAG_FILE_NAME);
        assert!(status_file.exists());
        assert_eq!(
            0,
            status_file.metadata().unwrap().len(),
            "success status.tag file must be empty"
        );

        let provision_query = super::ProvisionQuery::new(port, Some(Duration::from_millis(5)));
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(provision_status.finished, "provision_status.0 must be true");
        assert_eq!(
            0,
            provision_status.errorMessage.len(),
            "provision_status.1 must be empty"
        );

        let event_threads_initialized = provision_shared_state
            .get_event_log_threads_initialized()
            .await
            .unwrap();
        assert!(event_threads_initialized);

        // test reset key latch provision state
        super::key_latch_ready_state_reset(provision_shared_state.clone()).await;
        let provision_state = provision_shared_state.get_state().await.unwrap();
        assert!(!provision_state.contains(ProvisionFlags::KEY_LATCH_READY));
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(
            !provision_status.finished,
            "provision_status.0 must be false"
        );
        assert_eq!(
            0,
            provision_status.errorMessage.len(),
            "provision_status.1 must be empty"
        );

        // test key_latched ready again
        super::key_latched(
            cancellation_token.clone(),
            key_keeper_shared_state.clone(),
            telemetry_shared_state.clone(),
            provision_shared_state.clone(),
            agent_status_shared_state.clone(),
        )
        .await;
        let provision_state = provision_shared_state.get_state().await.unwrap();
        assert!(
            provision_state.contains(ProvisionFlags::ALL_READY),
            "ALL_READY must be true after key_latched again"
        );
        let provision_status = provision_query.get_provision_status_wait().await;
        assert!(provision_status.finished, "provision_status.0 must be true");
        assert_eq!(
            0,
            provision_status.errorMessage.len(),
            "provision_status.1 must be empty"
        );

        // stop listener
        cancellation_token.cancel();
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
    }
}
