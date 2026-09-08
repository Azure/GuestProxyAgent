// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the connection summary status.
//! The proxy agent status contains the 'connection summary' of the proxy server.
//! The proxy agent status contains the 'failed connection summary' of the proxy server.

use crate::common::logger;
use crate::common::result::Result;
use crate::proxy::proxy_connection::ConnectionLogger;
use crate::{common::error::Error, proxy::proxy_summary::ProxySummary};
use proxy_agent_shared::logger::LoggerLevel;
use proxy_agent_shared::proxy_agent_aggregate_status::ProxyConnectionSummary;
use proxy_agent_shared::secrets_redactor;
use proxy_agent_shared::telemetry::event_logger;
use proxy_agent_shared::time_buckets::TimeBucketedItem;
use std::collections::{hash_map, HashMap};
use tokio::sync::{mpsc, oneshot};

const BUCKET_DURATION_SECS: u64 = 900; // 15-minute buckets
const MAX_AGE_SECS: u64 = 4 * 3600; // 4 hours

enum ConnectionSummaryAction {
    AddOneConnection {
        summary: ProxySummary,
    },
    AddOneFailedConnection {
        summary: ProxySummary,
    },
    GetAllConnection {
        response: oneshot::Sender<Vec<ProxyConnectionSummary>>,
    },
    GetAllFailedConnection {
        response: oneshot::Sender<Vec<ProxyConnectionSummary>>,
    },
    ClearAll {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone, Debug)]
pub struct ConnectionSummarySharedState(mpsc::Sender<ConnectionSummaryAction>);

impl ConnectionSummarySharedState {
    pub fn start_new() -> Self {
        let (tx, mut rx) = mpsc::channel(100);
        tokio::spawn(async move {
            // The proxy connection summary from the proxy (using time-bucketed items)
            let mut proxy_summary: HashMap<String, TimeBucketedItem<ProxyConnectionSummary>> =
                HashMap::new();
            // The failed authenticate summary from the proxy (using time-bucketed items)
            let mut failed_authenticate_summary: HashMap<
                String,
                TimeBucketedItem<ProxyConnectionSummary>,
            > = HashMap::new();
            let max_age_duration = std::time::Duration::from_secs(MAX_AGE_SECS);
            let bucket_duration = std::time::Duration::from_secs(BUCKET_DURATION_SECS);

            while let Some(action) = rx.recv().await {
                match action {
                    ConnectionSummaryAction::AddOneConnection { mut summary } => {
                        // redact possbile secrets from the process command line in background before storing it in the time-bucketed item
                        summary.processCmdLine =
                            secrets_redactor::redact_secrets_string(summary.processCmdLine.clone());
                        let mut is_new_bucket = true;
                        let key = summary.to_key_string();
                        if let hash_map::Entry::Vacant(e) = proxy_summary.entry(key.clone()) {
                            e.insert(TimeBucketedItem::new(
                                summary.clone().into(),
                                bucket_duration,
                                max_age_duration,
                            ));
                        } else if let Some(connection_summary) = proxy_summary.get_mut(&key) {
                            is_new_bucket = connection_summary.add_one();
                        }
                        if is_new_bucket {
                            // if it's a new bucket, we log it to event logger
                            if let Ok(json) = serde_json::to_string(&summary) {
                                event_logger::write_event(
                                    LoggerLevel::Info,
                                    json,
                                    "log_connection_summary",
                                    "proxy_server",
                                    ConnectionLogger::CONNECTION_LOGGER_KEY,
                                );
                            };
                        }
                    }
                    ConnectionSummaryAction::AddOneFailedConnection { mut summary } => {
                        // redact possbile secrets from the process command line in background before storing it in the time-bucketed item
                        summary.processCmdLine =
                            secrets_redactor::redact_secrets_string(summary.processCmdLine.clone());
                        let mut is_new_bucket = true;
                        let key = summary.to_key_string();
                        if let hash_map::Entry::Vacant(e) =
                            failed_authenticate_summary.entry(key.clone())
                        {
                            e.insert(TimeBucketedItem::new(
                                summary.clone().into(),
                                bucket_duration,
                                max_age_duration,
                            ));
                        } else if let Some(connection_summary) =
                            failed_authenticate_summary.get_mut(&key)
                        {
                            is_new_bucket = connection_summary.add_one();
                        }
                        if is_new_bucket {
                            // if it's a new bucket, we log it to event logger
                            if let Ok(json) = serde_json::to_string(&summary) {
                                event_logger::write_event(
                                    LoggerLevel::Info,
                                    json,
                                    "log_connection_summary",
                                    "proxy_server",
                                    ConnectionLogger::CONNECTION_LOGGER_KEY,
                                );
                            };
                        }
                    }
                    ConnectionSummaryAction::GetAllConnection { response } => {
                        // Remove entries with no recent connections and collect summaries
                        proxy_summary.retain(|_, v| !v.is_empty());
                        let copy_summary: Vec<ProxyConnectionSummary> =
                            proxy_summary.values_mut().map(|v| v.to_item()).collect();
                        if let Err(summary) = response.send(copy_summary) {
                            logger::write_warning(format!(
                                "Failed to send response to ConnectionSummaryAction::GetAllConnection with summary count '{:?}'",
                                summary.len()
                            ));
                        }
                    }
                    ConnectionSummaryAction::GetAllFailedConnection { response } => {
                        // Remove entries with no recent failed connections and collect summaries
                        failed_authenticate_summary.retain(|_, v| !v.is_empty());
                        let copy_summary: Vec<ProxyConnectionSummary> = failed_authenticate_summary
                            .values_mut()
                            .map(|v| v.to_item())
                            .collect();
                        if let Err(summary) = response.send(copy_summary) {
                            logger::write_warning(format!(
                                "Failed to send response to ConnectionSummaryAction::GetAllFailedConnection with summary count '{:?}'",
                                summary.len()
                            ));
                        }
                    }
                    ConnectionSummaryAction::ClearAll { response } => {
                        // force clear all summaries
                        proxy_summary.clear();
                        failed_authenticate_summary.clear();
                        if response.send(()).is_err() {
                            logger::write_warning(
                                "Failed to send response to ConnectionSummaryAction::ClearAll"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        });

        ConnectionSummarySharedState(tx)
    }

    /// Add one connection summary
    /// It does implicitly removes expired time-bucketed items
    pub async fn add_one_connection_summary(&self, summary: ProxySummary) -> Result<()> {
        self.0
            .send(ConnectionSummaryAction::AddOneConnection { summary })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ConnectionSummaryAction::AddOneConnection".to_string(),
                    e.to_string(),
                )
            })?;
        Ok(())
    }

    /// Add one failed connection summary
    /// It does implicitly removes expired time-bucketed items
    pub async fn add_one_failed_connection_summary(&self, summary: ProxySummary) -> Result<()> {
        self.0
            .send(ConnectionSummaryAction::AddOneFailedConnection { summary })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ConnectionSummaryAction::AddOneFailedConnection".to_string(),
                    e.to_string(),
                )
            })?;
        Ok(())
    }

    /// Clear both connection summaries explicitly
    pub async fn clear_all_summary(&self) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(ConnectionSummaryAction::ClearAll {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ConnectionSummaryAction::ClearAll".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx
            .await
            .map_err(|e| Error::RecvError("ConnectionSummaryAction::ClearAll".to_string(), e))?;
        Ok(())
    }

    /// Get success connection summaries
    /// Returns a vector of ProxyConnectionSummary, implicitly removed expired time-bucketed items
    pub async fn get_all_connection_summary(&self) -> Result<Vec<ProxyConnectionSummary>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(ConnectionSummaryAction::GetAllConnection {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ConnectionSummaryAction::GetAllConnection".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx.await.map_err(|e| {
            Error::RecvError("ConnectionSummaryAction::GetAllConnection".to_string(), e)
        })
    }

    /// Get failed connection summaries
    /// Returns a vector of ProxyConnectionSummary, implicitly removed expired time-bucketed items
    pub async fn get_all_failed_connection_summary(&self) -> Result<Vec<ProxyConnectionSummary>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(ConnectionSummaryAction::GetAllFailedConnection {
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ConnectionSummaryAction::GetAllFailedConnection".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx.await.map_err(|e| {
            Error::RecvError(
                "ConnectionSummaryAction::GetAllFailedConnection".to_string(),
                e,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::proxy_summary::ProxySummary;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_agent_status_shared_state() {
        let connection_summary_shared_state = ConnectionSummarySharedState::start_new();

        let connection_summary = ProxySummary {
            id: 1,
            method: "GET".to_string(),
            url: "/status".to_string(),
            clientIp: "127.0.0.1".to_string(),
            clientPort: 6080,
            ip: "127.0.0.1".to_string(),
            port: 8080,
            addressFamily: "IPv4".to_string(),
            userId: 999,
            userName: "user1".to_string(),
            userGroups: vec!["group1".to_string()],
            processFullPath: PathBuf::from("C:\\path\\to\\process.exe"),
            processCmdLine: "process --arg1 --arg2".to_string(),
            runAsElevated: true,
            responseStatus: "200 OK".to_string(),
            elapsedTime: 123,
            errorDetails: "".to_string(),
        };
        connection_summary_shared_state
            .add_one_connection_summary(connection_summary.clone())
            .await
            .unwrap();
        let get_all_connection_summary = connection_summary_shared_state
            .get_all_connection_summary()
            .await
            .unwrap();
        assert_eq!(1, get_all_connection_summary.len());
        assert_eq!(1, get_all_connection_summary[0].count);

        let mut ipv6_summary = connection_summary.clone();
        ipv6_summary.addressFamily = "IPv6".to_string();
        assert_ne!(
            connection_summary.to_key_string(),
            ipv6_summary.to_key_string()
        );
        let telemetry_json = serde_json::to_string(&ipv6_summary).unwrap();
        assert!(telemetry_json.contains(r#""addressFamily":"IPv6""#));

        let failed_connection_summary = ProxySummary {
            id: 2,
            method: "GET".to_string(),
            url: "/status".to_string(),
            clientIp: "127.0.0.1".to_string(),
            clientPort: 6080,
            ip: "127.0.0.1".to_string(),
            port: 8080,
            addressFamily: "IPv4".to_string(),
            userId: 999,
            userName: "user1".to_string(),
            userGroups: vec!["group1".to_string()],
            processFullPath: PathBuf::from("C:\\path\\to\\process.exe"),
            processCmdLine: "process --arg1 --arg2".to_string(),
            runAsElevated: true,
            responseStatus: "500 Internal Server Error".to_string(),
            elapsedTime: 123,
            errorDetails: "Some error occurred".to_string(),
        };
        connection_summary_shared_state
            .add_one_failed_connection_summary(failed_connection_summary.clone())
            .await
            .unwrap();
        let get_all_failed_connection_summary = connection_summary_shared_state
            .get_all_failed_connection_summary()
            .await
            .unwrap();
        assert_eq!(1, get_all_failed_connection_summary.len());

        // clear all summaries
        connection_summary_shared_state
            .clear_all_summary()
            .await
            .unwrap();
        let get_all_connection_summary = connection_summary_shared_state
            .get_all_connection_summary()
            .await
            .unwrap();
        assert_eq!(0, get_all_connection_summary.len());
    }
}
