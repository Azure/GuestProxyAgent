// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct HandlerEnvironment {
    pub logFolder: String,
    pub statusFolder: String,
    pub configFolder: String,
    pub heartbeatFile: String,
    pub deploymentid: Option<String>,
    pub rolename: Option<String>,
    pub instance: Option<String>,
    pub hostResolverAddress: Option<String>,
    pub eventsFolder: String,
}
impl HandlerEnvironment {
    pub fn clone(&self) -> Self {
        HandlerEnvironment {
            logFolder: self.logFolder.clone(),
            statusFolder: self.statusFolder.clone(),
            configFolder: self.configFolder.clone(),
            heartbeatFile: self.heartbeatFile.clone(),
            deploymentid: self.deploymentid.clone(),
            rolename: self.rolename.clone(),
            instance: self.instance.clone(),
            hostResolverAddress: self.hostResolverAddress.clone(),
            eventsFolder: self.eventsFolder.clone(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Handler {
    pub handlerEnvironment: HandlerEnvironment,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct StatusObj {
    pub name: String,
    pub operation: String,
    pub configurationAppliedTime: String,
    pub status: String,
    pub code: i32,
    pub formattedMessage: FormattedMessage,
    pub substatus: Vec<SubStatus>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct FormattedMessage {
    pub lang: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct SubStatus {
    pub name: String,
    pub status: String,
    pub code: i32,
    pub formattedMessage: FormattedMessage,
}
impl Default for SubStatus {
    fn default() -> Self {
        SubStatus {
            name: "".to_string(),
            status: "".to_string(),
            code: 0,
            formattedMessage: FormattedMessage {
                lang: "".to_string(),
                message: "".to_string(),
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct TopLevelStatus {
    pub version: String,
    pub timestampUTC: String,
    pub status: StatusObj,
}
#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct TopLevelHeartbeat {
    pub version: String,
    pub heartbeat: HeartbeatObj,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct HeartbeatObj {
    pub status: String,
    pub code: String,
    pub formattedMessage: FormattedMessage,
}
#[cfg(test)]
mod tests {
    #[test]
    fn handler_env_test() {
        // test handler env, init, serialize, deserialize and compare original and deserialized

        //Create raw handler environment json string
        let json_handler: &str = r#"[{
            "version": 1.0,
            "handlerEnvironment": {
                "logFolder": "log", 
                "configFolder": "config", 
                "statusFolder": "status", 
                "heartbeatFile": "heartbeat.json", 
                "deploymentid": "000", 
                "rolename": "test_rolename", 
                "instance": "test_instance", 
                "hostResolverAddress": "000", 
                "eventsFolder": "test_kusto" 
            }
        }]"#;

        //Deserialize handler environment json string
        let handler_env_obj: Vec<super::Handler> = serde_json::from_str(json_handler).unwrap();
        let handlerEnvironment = handler_env_obj[0].handlerEnvironment.clone();

        assert_eq!(
            "log".to_string(),
            handlerEnvironment.logFolder,
            "logFolder mismatch"
        );

        assert_eq!(
            "config".to_string(),
            handlerEnvironment.configFolder,
            "configFolder mismatch"
        );

        assert_eq!(
            "status".to_string(),
            handlerEnvironment.statusFolder,
            "statusFolder mismatch"
        );

        assert_eq!(
            "heartbeat.json".to_string(),
            handlerEnvironment.heartbeatFile,
            "heartbeatFile mismatch"
        );

        match handlerEnvironment.deploymentid {
            Some(deploymentid) => {
                assert_eq!("000".to_string(), deploymentid, "deploymentid mismatch")
            }
            None => assert!(false, "deploymentid not found"),
        }
        
        match handlerEnvironment.rolename {
            Some(rolename) => assert_eq!("test_rolename".to_string(), rolename, "rolename mismatch"),
            None => assert!(false, "rolename not found"),
        }
    }

    #[test]
    fn status_obj_test() {
        // test status obj, init, serialize, deserialize and compare original and deserialized

        //Create raw status obj json string
        let json_status: &str = r#"{
            "version": "1.0",
            "timestampUTC": "2021-01-01T00:00:00.000Z",
            "status": {
                "name": "test_status_name",
                "operation": "test_operation",
                "configurationAppliedTime": "2021-01-01T00:00:00.000Z",
                "code": 0,
                "status": "test_status",
                "formattedMessage": {
                    "lang": "en-US",
                    "message": "test_formatted_message"
                },
                "substatus": [{
                    "name": "test_substatus_name",
                    "status": "test_substatus",
                    "code": 0,
                    "formattedMessage": {
                        "lang": "en-US",
                        "message": "test_substatus_formatted_message"
                    }
                }]
            }
        }"#;

        //Deserialize status obj json string
        let status_obj: super::TopLevelStatus = serde_json::from_str(json_status).unwrap();
        let status = status_obj.status;

        assert_eq!(
            "1.0".to_string(), 
            status_obj.version, 
            "version mismatch"
        );

        assert_eq!(
            "2021-01-01T00:00:00.000Z".to_string(),
            status_obj.timestampUTC,
            "timestampUTC mismatch"
        );

        assert_eq!(
            "test_status_name".to_string(), 
            status.name, 
            "name mismatch"
        );

        assert_eq!(
            0, 
            status.code, 
            "code mismatch"
        );

        assert_eq!(
            "test_status".to_string(), 
            status.status, 
            "status mismatch"
        );
    }

    #[test]
    fn heartbeat_obj_test() {
        // test heartbeat obj, init, serialize, deserialize and compare original and deserialized

        //Create raw heartbeat obj json string
        let json_heartbeat: &str = r#"{
            "version": "1.0",
            "heartbeat": {
                "status": "test_status",
                "code": "0",
                "formattedMessage": {
                    "lang": "en-US",
                    "message": "test_formatted_message"
                }
            }
        }"#;

        //Deserialize heartbeat obj json string
        let heartbeat_obj: super::TopLevelHeartbeat = serde_json::from_str(json_heartbeat).unwrap();
        let heartbeat = heartbeat_obj.heartbeat;

        assert_eq!(
            "1.0".to_string(), 
            heartbeat_obj.version, 
            "version mismatch"
        );

        assert_eq!(
            "test_status".to_string(),
            heartbeat.status,
            "status mismatch"
        );

        assert_eq!(
            "0".to_string(), 
            heartbeat.code, 
            "code mismatch"
        );
    }
}
