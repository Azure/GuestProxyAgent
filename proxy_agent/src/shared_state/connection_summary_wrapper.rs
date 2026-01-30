// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to interact with the connection summary status.
//! The proxy agent status contains the 'connection summary' of the proxy server.
//! The proxy agent status contains the 'failed connection summary' of the proxy server.

use crate::common::logger;
use crate::common::result::Result;
use crate::{common::error::Error, proxy::proxy_summary::ProxySummary};
use proxy_agent_shared::proxy_agent_aggregate_status::ProxyConnectionSummary;
use proxy_agent_shared::time_buckets::TimeBucketedItem;
use std::collections::{hash_map, HashMap};
use tokio::sync::{mpsc, oneshot};

const BUCKET_DURATION_SECS: u64 = 900; // 15-minute buckets
const MAX_AGE_SECS: u64 = 4 * 3600; // 4 hours

enum ConnectionSummaryAction {
    AddOneConnection {
        summary: ProxySummary,
        response: oneshot::Sender<bool>,
    },
    AddOneFailedConnection {
        summary: ProxySummary,
        response: oneshot::Sender<bool>,
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
                    ConnectionSummaryAction::AddOneConnection { summary, response } => {
                        let mut is_new_bucket = true;
                        let key = summary.to_key_string();
                        if let hash_map::Entry::Vacant(e) = proxy_summary.entry(key.clone()) {
                            e.insert(TimeBucketedItem::new(
                                summary.into(),
                                bucket_duration,
                                max_age_duration,
                            ));
                        } else if let Some(connection_summary) = proxy_summary.get_mut(&key) {
                            is_new_bucket = connection_summary.add_one();
                        }
                        if response.send(is_new_bucket).is_err() {
                            logger::write_warning("Failed to send response to ConnectionSummaryAction::AddOneConnection".to_string());
                        }
                    }
                    ConnectionSummaryAction::AddOneFailedConnection { summary, response } => {
                        let mut is_new_bucket = true;
                        let key = summary.to_key_string();
                        if let hash_map::Entry::Vacant(e) =
                            failed_authenticate_summary.entry(key.clone())
                        {
                            e.insert(TimeBucketedItem::new(
                                summary.into(),
                                bucket_duration,
                                max_age_duration,
                            ));
                        } else if let Some(connection_summary) =
                            failed_authenticate_summary.get_mut(&key)
                        {
                            is_new_bucket = connection_summary.add_one();
                        }
                        if response.send(is_new_bucket).is_err() {
                            logger::write_warning("Failed to send response to ConnectionSummaryAction::AddOneFailedConnection".to_string());
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
                        let copy_summary: Vec<ProxyConnectionSummary> =
                            failed_authenticate_summary.values_mut().map(|v| v.to_item()).collect();
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
     /// Returns true if a new time-bucketed item was created.
    /// It does implicitly removes expired time-bucketed items
    pub async fn add_one_connection_summary(&self, summary: ProxySummary) -> Result<bool> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(ConnectionSummaryAction::AddOneConnection {
                summary,
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ConnectionSummaryAction::AddOneConnection".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx.await.map_err(|e| {
            Error::RecvError("ConnectionSummaryAction::AddOneConnection".to_string(), e)
        })
    }

    /// Add one failed connection summary
    /// Returns true if a new time bucket is created for this summary, false otherwise
    /// It does implicitly removes expired time-bucketed items
    pub async fn add_one_failed_connection_summary(&self, summary: ProxySummary) -> Result<bool> {
        let (response_tx, response_rx) = oneshot::channel();
        self.0
            .send(ConnectionSummaryAction::AddOneFailedConnection {
                summary,
                response: response_tx,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "ConnectionSummaryAction::AddOneFailedConnection".to_string(),
                    e.to_string(),
                )
            })?;
        response_rx.await.map_err(|e| {
            Error::RecvError(
                "ConnectionSummaryAction::AddOneFailedConnection".to_string(),
                e,
            )
        })
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

        let failed_connection_summary = ProxySummary {
            id: 2,
            method: "GET".to_string(),
            url: "/status".to_string(),
            clientIp: "127.0.0.1".to_string(),
            clientPort: 6080,
            ip: "127.0.0.1".to_string(),
            port: 8080,
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
