// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::http::request::Request;
use crate::common::http::{self, response::Response};
use crate::common::logger;
use crate::key_keeper;
use crate::key_keeper::key::{Key, KeyStatus};
use once_cell::sync::Lazy;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use uuid::Uuid;

static EMPTY_GUID: Lazy<String> = Lazy::new(|| "00000000-0000-0000-0000-000000000000".to_string());
static GUID: Lazy<String> = Lazy::new(|| Uuid::new_v4().to_string());
static mut CURRENT_STATE: Lazy<String> =
    Lazy::new(|| String::from(key_keeper::MUST_SIG_WIRESERVER));

pub fn start(ip: String, port: u16) {
    logger::write_information("WireServer starting...".to_string());
    let listener = TcpListener::bind(format!("{}:{}", ip, port)).unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        if handle_request(stream, ip.to_string(), port) == false {
            return;
        }
    }
}

pub fn stop(ip: String, port: u16) {
    let stop_request = Request::new("stop".to_string(), "GET".to_string());
    match TcpStream::connect(format!("{}:{}", ip, port)) {
        Ok(mut client) => {
            _ = client.write_all(&stop_request.to_raw_bytes());
            _ = client.flush();
        }
        Err(_) => {}
    }
}

fn handle_request(mut stream: TcpStream, ip: String, port: u16) -> bool {
    logger::write_information("WireServer processing request.".to_string());

    let request = http::receive_request_data(&stream).unwrap();
    if request.url == "stop" {
        return false;
    }
    let path: String;
    match request.get_url() {
        Some(url) => {
            path = url.path().to_string().chars().skip(1).collect();
        }
        None => path = request.url.chars().skip(1).collect(),
    }
    let segments: Vec<&str> = path.split('/').collect();

    let mut response = Response::from_status(Response::OK.to_string());
    if request.method == "GET" {
        if segments.len() > 0 && segments[0] == "secure-channel" {
            if segments.len() > 1 && segments[1] == "status" {
                // get key status
                let status_response = r#"{
                    "authorizationScheme": "Azure-HMAC-SHA256",
                    "keyDeliveryMethod": "http",
                    "keyGuid": "",
                    "requiredClaimsHeaderPairs": [
                        "isRoot"
                    ],
                    "secureChannelState": "Wireserver",
                    "version": "1.0"
                }"#;
                let mut status: KeyStatus = serde_json::from_str(status_response).unwrap();
                unsafe {
                    if *CURRENT_STATE == key_keeper::DISABLE_STATE {
                        status.secureChannelState = Some(key_keeper::DISABLE_STATE.to_string());
                    } else {
                        status.secureChannelState = Some( key_keeper::MUST_SIG_WIRESERVER.to_string());
                    }
                }
                response.set_body_as_string(serde_json::to_string(&status).unwrap());
            }
        } else if segments.len() > 0 && segments[0] == "machine?comp=goalstate" {
            let goal_state_str = r#"<?xml version="1.0" encoding="utf-8"?>
            <GoalState xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="goalstate10.xsd">
              <Version>2015-04-05</Version>
              <Incarnation>16</Incarnation>
              <Machine>
                <ExpectedState>Started</ExpectedState>
                <StopRolesDeadlineHint>300000</StopRolesDeadlineHint>
                <LBProbePorts>
                  <Port>16001</Port>
                </LBProbePorts>
                <ExpectHealthReport>TRUE</ExpectHealthReport>
                <Package>http://##ip##:##port##/machine/?comp=package&amp;incarnation=Win8-Win8_2.7.32211.3_221108-1339_GuestAgentPackage_NoWER.zip</Package>
                <PackageIncarnation>Win8-Win8_2.7.32211.3_221108-1339_GuestAgentPackage_NoWER.zip</PackageIncarnation>
              </Machine>
              <Container>
                <ContainerId>374188df-b0a2-456a-a7b2-83f28b18d36f</ContainerId>
                <RoleInstanceList>
                  <RoleInstance>
                    <InstanceId>7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker_IN_0</InstanceId>
                    <State>Started</State>
                    <Configuration>
                      <HostingEnvironmentConfig>http://##ip##:##port##/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=hostingEnvironmentConfig&amp;incarnation=16</HostingEnvironmentConfig>
                      <SharedConfig>http://##ip##:##port##/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=sharedConfig&amp;incarnation=16</SharedConfig>
                      <ExtensionsConfig>http://##ip##:##port##/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=extensionsConfig&amp;incarnation=16</ExtensionsConfig>
                      <FullConfig>http://##ip##:##port##/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=fullConfig&amp;incarnation=16</FullConfig>
                      <Certificates>http://##ip##:##port##/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=certificates&amp;incarnation=16</Certificates>
                      <ConfigName>7d2798bb72a0413d9a60b355277df726.132.7d2798bb72a0413d9a60b355277df726.78.TenantAdminApi.Worker_IN_0.1.xml</ConfigName>
                    </Configuration>
                  </RoleInstance>
                </RoleInstanceList>
              </Container>
            </GoalState>"#;
            let goal_state_str = goal_state_str.replace("##ip##", &ip);
            let goal_state_str = goal_state_str.replace("##port##", &port.to_string());
            response.set_body_as_string(goal_state_str.to_string());
        } else if path.starts_with("machine/")
            && path.contains("type=sharedConfig")
        {
            let shared_config_str = r#"<?xml version="1.0" encoding="utf-8"?>
            <SharedConfig version="1.0.0.0" goalStateIncarnation="16">
              <Deployment name="7d2798bb72a0413d9a60b355277df726" guid="{25a2c1a1-2986-4d1c-bd37-6abe8571218d}" incarnation="132" isNonCancellableTopologyChangeEnabled="false">
                <Service name="TenantAdminApi.Cloud" guid="{00000000-0000-0000-0000-000000000000}" />
                <ServiceInstance name="7d2798bb72a0413d9a60b355277df726.78" guid="{2733116f-69db-411d-91a0-a1f55849ba23}" />
              </Deployment>
              <Incarnation number="1" instance="TenantAdminApi.Worker_IN_0" guid="{b0b40fde-461e-461b-a451-af58347321a9}" />
              <Role guid="{953935f8-9317-74e0-4236-7854486dd013}" name="TenantAdminApi.Worker" settleTimeSeconds="0" />
              <LoadBalancerSettings timeoutSeconds="32" waitLoadBalancerProbeCount="8">
                <Probes>
                  <Probe name="DataAPI.Worker" />
                  <Probe name="EE594D782E1C6640A88F13C68ACE44E2" />
                  <Probe name="7DFC3BF5C3491DDCE7AE643C84D4D28D" />
                </Probes>
              </LoadBalancerSettings>
              <OutputEndpoints />
              <Instances>
                <Instance id="TenantAdminApi.Worker_IN_0" address="10.1.64.6">
                  <FaultDomains randomId="0" updateId="0" updateCount="1" />
                  <InputEndpoints>
                    <Endpoint name="HttpsEndpoint" address="10.1.64.6:443" protocol="https" certificateId="sha1:0553937140F34E9E22A9032E7CA0EE478D3E5662" enableClientCertNegotiation="false" hostName="dodce-a-01-api-interfaces-byoip" isPublic="true" loadBalancedPublicAddress="52.127.68.35:443" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
                      <LocalPorts>
                        <LocalPortRange from="443" to="443" />
                      </LocalPorts>
                    </Endpoint>
                  </InputEndpoints>
                </Instance>
              </Instances>
            </SharedConfig>"#;
            response.set_body_as_string(shared_config_str.to_string());
        } else if path.starts_with("metadata/instance") {
            let response_data = r#"{
                "compute": {
                    "azEnvironment": "AZUREPUBLICCLOUD",
                    "additionalCapabilities": {
                        "hibernationEnabled": "true"
                    },
                    "hostGroup": {
                      "id": "testHostGroupId"
                    }, 
                    "extendedLocation": {
                        "type": "edgeZone",
                        "name": "microsoftlosangeles"
                    },
                    "evictionPolicy": "",
                    "isHostCompatibilityLayerVm": "true",
                    "licenseType":  "Windows_Client",
                    "location": "westus",
                    "name": "examplevmname",
                    "offer": "WindowsServer",
                    "osProfile": {
                        "adminUsername": "admin",
                        "computerName": "examplevmname",
                        "disablePasswordAuthentication": "true"
                    },
                    "osType": "Windows",
                    "placementGroupId": "f67c14ab-e92c-408c-ae2d-da15866ec79a",
                    "plan": {
                        "name": "planName",
                        "product": "planProduct",
                        "publisher": "planPublisher"
                    },
                    "platformFaultDomain": "36",
                    "platformSubFaultDomain": "",        
                    "platformUpdateDomain": "42",
                    "priority": "Regular",
                    "publicKeys": [{
                            "keyData": "ssh-rsa 0",
                            "path": "/home/user/.ssh/authorized_keys0"
                        },
                        {
                            "keyData": "ssh-rsa 1",
                            "path": "/home/user/.ssh/authorized_keys1"
                        }
                    ],
                    "publisher": "RDFE-Test-Microsoft-Windows-Server-Group",
                    "resourceGroupName": "macikgo-test-may-23",
                    "resourceId": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/macikgo-test-may-23/providers/Microsoft.Compute/virtualMachines/examplevmname",
                    "securityProfile": {
                        "secureBootEnabled": "true",
                        "virtualTpmEnabled": "false",
                        "encryptionAtHost": "true",
                        "securityType": "TrustedLaunch"
                    },
                    "sku": "2019-Datacenter",
                    "storageProfile": {
                        "dataDisks": [{
                            "bytesPerSecondThrottle": "979202048",
                            "caching": "None",
                            "createOption": "Empty",
                            "diskCapacityBytes": "274877906944",
                            "diskSizeGB": "1024",
                            "image": {
                              "uri": ""
                            },
                            "isSharedDisk": "false",
                            "isUltraDisk": "true",
                            "lun": "0",
                            "managedDisk": {
                              "id": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/macikgo-test-may-23/providers/Microsoft.Compute/disks/exampledatadiskname",
                              "storageAccountType": "StandardSSD_LRS"
                            },
                            "name": "exampledatadiskname",
                            "opsPerSecondThrottle": "65280",
                            "vhd": {
                              "uri": ""
                            },
                            "writeAcceleratorEnabled": "false"
                        }],
                        "imageReference": {
                            "id": "",
                            "offer": "WindowsServer",
                            "publisher": "MicrosoftWindowsServer",
                            "sku": "2019-Datacenter",
                            "version": "latest"
                        },
                        "osDisk": {
                            "caching": "ReadWrite",
                            "createOption": "FromImage",
                            "diskSizeGB": "30",
                            "diffDiskSettings": {
                                "option": "Local"
                            },
                            "encryptionSettings": {
                              "enabled": "false",
                              "diskEncryptionKey": {
                                "sourceVault": {
                                  "id": "/subscriptions/test-source-guid/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/test-kv"
                                },
                                "secretUrl": "https://test-disk.vault.azure.net/secrets/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx"
                              },
                              "keyEncryptionKey": {
                                "sourceVault": {
                                  "id": "/subscriptions/test-key-guid/resourceGroups/testrg/providers/Microsoft.KeyVault/vaults/test-kv"
                                },
                                "keyUrl": "https://test-key.vault.azure.net/secrets/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx"
                              }
                            },
                            "image": {
                                "uri": ""
                            },
                            "managedDisk": {
                                "id": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/macikgo-test-may-23/providers/Microsoft.Compute/disks/exampleosdiskname",
                                "storageAccountType": "StandardSSD_LRS"
                            },
                            "name": "exampleosdiskname",
                            "osType": "Windows",
                            "vhd": {
                                "uri": ""
                            },
                            "writeAcceleratorEnabled": "false"
                        },
                        "resourceDisk": {
                            "size": "4096"
                        }
                    },
                    "subscriptionId": "xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx",
                    "tags": "baz:bash;foo:bar",
                    "userData": "Zm9vYmFy",
                    "version": "15.05.22",
                    "virtualMachineScaleSet": {
                        "id": "/subscriptions/xxxxxxxx-xxxxx-xxx-xxx-xxxx/resourceGroups/resource-group-name/providers/Microsoft.Compute/virtualMachineScaleSets/virtual-machine-scale-set-name"
                    },
                    "vmId": "02aab8a4-74ef-476e-8182-f6d2ba4166a6",
                    "vmScaleSetName": "crpteste9vflji9",
                    "vmSize": "Standard_A3",
                    "zone": ""
                },
                "network": {
                    "interface": [{
                        "ipv4": {
                           "ipAddress": [{
                                "privateIpAddress": "10.144.133.132",
                                "publicIpAddress": ""
                            }],
                            "subnet": [{
                                "address": "10.144.133.128",
                                "prefix": "26"
                            }]
                        },
                        "ipv6": {
                            "ipAddress": [
                             ]
                        },
                        "macAddress": "0011AAFFBB22"
                    }]
                }
            }"#;
            response.set_body_as_string(response_data.to_string());
        }
    } else if request.method == "POST" {
        if segments.len() > 0 && segments[0] == "secure-channel" {
            if segments.len() > 1 && segments[1] == "key" {
                // get key details
                let key_response = r#"{
                        "authorizationScheme": "Azure-HMAC-SHA256",        
                        "guid": "",        
                        "issued": "2021-05-05T 12:00:00Z",        
                        "key": "4A404E635266556A586E3272357538782F413F4428472B4B6250645367566B59"        
                    }"#;
                let mut key: Key = serde_json::from_str(key_response).unwrap();
                unsafe {
                    if *CURRENT_STATE == key_keeper::DISABLE_STATE {
                        key.guid = EMPTY_GUID.to_string();
                    } else {
                        key.guid = GUID.to_string();
                    }
                }
                response.set_body_as_string(serde_json::to_string(&key).unwrap());
            }
        } else if segments.len() > 0 && segments[0] == "machine" {
            if segments.len() > 1 && segments[1] == "?comp=telemetrydata" {
                // post telemetry data
                // send continue response
                let mut continue_response = Response::from_status(Response::CONTINUE.to_string());
                _ = stream.write_all(continue_response.to_raw_string().as_bytes());
                _ = stream.flush();

                // receive the data
                let content_length = request.headers.get_content_length().unwrap();

                // receive body content from client
                http::receive_body(&stream, content_length).unwrap();
            }
        }
    }

    _ = stream.write_all(response.to_raw_string().as_bytes());
    _ = stream.flush();
    logger::write_information("WireServer processed request.".to_string());

    true
}

pub fn set_secure_channel_state(enabled: bool) {
    if enabled {
        unsafe {
            *CURRENT_STATE = key_keeper::MUST_SIG_WIRESERVER.to_string();
        }
    } else {
        unsafe {
            *CURRENT_STATE = key_keeper::DISABLE_STATE.to_string();
        }
    }
}
