// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::error::Error;
use crate::common::logger;
use crate::common::result::Result;
use crate::key_keeper::key::AuthorizationItem;
use crate::proxy::authorization_rules::ComputedAuthorizationItem;
use tokio::sync::{mpsc, oneshot};

/// The AccessControlAction enum represents the actions that can be performed on the Access Control
enum AccessControlAction {
    SetWireServer {
        rules: Option<ComputedAuthorizationItem>,
        response: oneshot::Sender<()>,
    },
    GetWireServer {
        response: oneshot::Sender<Option<ComputedAuthorizationItem>>,
    },
    SetImds {
        rules: Option<ComputedAuthorizationItem>,
        response: oneshot::Sender<()>,
    },
    GetImds {
        response: oneshot::Sender<Option<ComputedAuthorizationItem>>,
    },
    SetHostGA {
        rules: Option<ComputedAuthorizationItem>,
        response: oneshot::Sender<()>,
    },
    GetHostGA {
        response: oneshot::Sender<Option<ComputedAuthorizationItem>>,
    },
}

/// The AccessControlState struct is used to send actions to the Access Control Rules related shared state fields
#[derive(Clone, Debug)]
pub struct AccessControlSharedState(mpsc::Sender<AccessControlAction>);

impl AccessControlSharedState {
    pub fn start_new() -> Self {
        let (sender, mut receiver) = mpsc::channel(100);

        tokio::spawn(async move {
            // The authorization rules for the WireServer endpoints
            let mut wireserver_rules: Option<ComputedAuthorizationItem> = None;
            // The authorization rules for the IMDS endpoints
            let mut imds_rules: Option<ComputedAuthorizationItem> = None;
            // The authorization rules for the HostGAPlugin endpoints
            let mut hostga_rules: Option<ComputedAuthorizationItem> = None;
            loop {
                match receiver.recv().await {
                    Some(AccessControlAction::SetWireServer { rules, response }) => {
                        wireserver_rules = rules;
                        if response.send(()).is_err() {
                            logger::write_warning(
                                "Failed to send response to AccessControlAction::SetWireServer"
                                    .to_string(),
                            );
                        }
                    }
                    Some(AccessControlAction::GetWireServer { response }) => {
                        if response.send(wireserver_rules.clone()).is_err() {
                            logger::write_warning(
                                "Failed to send response to AccessControlAction::GetWireServer"
                                    .to_string(),
                            );
                        }
                    }
                    Some(AccessControlAction::SetImds { rules, response }) => {
                        imds_rules = rules;
                        if response.send(()).is_err() {
                            logger::write_warning(
                                "Failed to send response to AccessControlAction::SetImds"
                                    .to_string(),
                            );
                        }
                    }
                    Some(AccessControlAction::GetImds { response }) => {
                        if response.send(imds_rules.clone()).is_err() {
                            logger::write_warning(
                                "Failed to send response to AccessControlAction::GetImds"
                                    .to_string(),
                            );
                        }
                    }
                    Some(AccessControlAction::SetHostGA { rules, response }) => {
                        hostga_rules = rules;
                        if response.send(()).is_err() {
                            logger::write_warning(
                                "Failed to send response to AccessControlAction::SetHostGA"
                                    .to_string(),
                            );
                        }
                    }
                    Some(AccessControlAction::GetHostGA { response }) => {
                        if response.send(hostga_rules.clone()).is_err() {
                            logger::write_warning(
                                "Failed to send response to AccessControlAction::GetHostGA"
                                    .to_string(),
                            );
                        }
                    }
                    None => break,
                }
            }
        });

        Self(sender)
    }

    pub async fn set_wireserver_rules(&self, rules: Option<AuthorizationItem>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(AccessControlAction::SetWireServer {
                rules: rules.map(ComputedAuthorizationItem::from_authorization_item),
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AccessControlAction::SetWireServer".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("AccessControlAction::GetWireServer".to_string(), e))
    }

    pub async fn get_wireserver_rules(&self) -> Result<Option<ComputedAuthorizationItem>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(AccessControlAction::GetWireServer { response })
            .await
            .map_err(|e| {
                Error::SendError(
                    "AccessControlAction::GetWireServer".to_string(),
                    e.to_string(),
                )
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("AccessControlAction::GetWireServer".to_string(), e))
    }

    pub async fn set_imds_rules(&self, rules: Option<AuthorizationItem>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(AccessControlAction::SetImds {
                rules: rules.map(ComputedAuthorizationItem::from_authorization_item),
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("AccessControlAction::SetImds".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("AccessControlAction::SetImds".to_string(), e))
    }

    pub async fn get_imds_rules(&self) -> Result<Option<ComputedAuthorizationItem>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(AccessControlAction::GetImds { response })
            .await
            .map_err(|e| {
                Error::SendError("AccessControlAction::GetImds".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("AccessControlAction::GetImds".to_string(), e))
    }

    pub async fn set_hostga_rules(&self, rules: Option<AuthorizationItem>) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(AccessControlAction::SetHostGA {
                rules: rules.map(ComputedAuthorizationItem::from_authorization_item),
                response,
            })
            .await
            .map_err(|e| {
                Error::SendError("AccessControlAction::SetHostGA".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("AccessControlAction::GetHostGA".to_string(), e))
    }

    pub async fn get_hostga_rules(&self) -> Result<Option<ComputedAuthorizationItem>> {
        let (response, receiver) = oneshot::channel();
        self.0
            .send(AccessControlAction::GetHostGA { response })
            .await
            .map_err(|e| {
                Error::SendError("AccessControlAction::GetHostGA".to_string(), e.to_string())
            })?;
        receiver
            .await
            .map_err(|e| Error::RecvError("AccessControlAction::GetHostGA".to_string(), e))
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::authorization_rules;

    use super::*;

    #[tokio::test]
    async fn test_access_control_shared_state() {
        let access_control = AccessControlSharedState::start_new();

        // test WireServer Rule
        let rule_id = "test_rule_id";
        let rules = AuthorizationItem {
            defaultAccess: "allow".to_string(),
            mode: "audit".to_string(),
            id: rule_id.to_string(),
            rules: None,
        };
        access_control
            .set_wireserver_rules(Some(rules.clone()))
            .await
            .unwrap();
        let retrieved_rules = access_control.get_wireserver_rules().await.unwrap();
        assert!(retrieved_rules.is_some());
        let retrieved_rules = retrieved_rules.unwrap();
        assert_eq!(rules.id, retrieved_rules.id);
        assert_eq!(true, retrieved_rules.defaultAllowed);
        assert_eq!(
            authorization_rules::AuthorizationMode::Audit,
            retrieved_rules.mode
        );
        assert_eq!(0, retrieved_rules.privilegeAssignments.len());
        assert_eq!(0, retrieved_rules.privileges.len());
        assert_eq!(0, retrieved_rules.identities.len());

        // test IMDS Rule
        let rules = AuthorizationItem {
            defaultAccess: "deny".to_string(),
            mode: "enforce".to_string(),
            id: rule_id.to_string(),
            rules: None,
        };
        access_control
            .set_imds_rules(Some(rules.clone()))
            .await
            .unwrap();
        let retrieved_rules = access_control.get_imds_rules().await.unwrap();
        assert!(retrieved_rules.is_some());
        let retrieved_rules = retrieved_rules.unwrap();
        assert_eq!(rules.id, retrieved_rules.id);
        assert_eq!(false, retrieved_rules.defaultAllowed);
        assert_eq!(
            authorization_rules::AuthorizationMode::Enforce,
            retrieved_rules.mode
        );
    }
}
