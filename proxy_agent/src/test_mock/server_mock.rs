// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{http, logger};
use crate::key_keeper;
use crate::key_keeper::key::{Key, KeyStatus};
use crate::shared_state::{proxy_listener_wrapper, shared_state_wrapper, SharedState};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper_util::rt::TokioIo;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use uuid::Uuid;

static EMPTY_GUID: Lazy<String> = Lazy::new(|| "00000000-0000-0000-0000-000000000000".to_string());
static GUID: Lazy<String> = Lazy::new(|| Uuid::new_v4().to_string());
static mut CURRENT_STATE: Lazy<String> =
    Lazy::new(|| String::from(key_keeper::MUST_SIG_WIRESERVER));

pub async fn start(
    ip: String,
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    logger::write_information("Mock Server starting...".to_string());
    let addr = format!("{}:{}", ip, port);
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!("Listening on http://{}", addr);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok((stream, client_addr)) => (stream, client_addr),
            Err(e) => {
                logger::write_warning(format!("ProxyListener accept error {}", e));
                continue;
            }
        };

        if shared_state_wrapper::get_cancellation_token(shared_state.clone()).is_cancelled() {
            let message = "Stop signal received, stop the listener.";
            logger::write_warning(message.to_string());
            return Ok(());
        }
        let ip = ip.to_string();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let ip = ip.to_string();
            let service = service_fn(move |req| handle_request(ip.to_string(), port, req));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

pub fn stop(ip: String, port: u16, shared_state: Arc<Mutex<SharedState>>) {
    proxy_listener_wrapper::set_shutdown(shared_state.clone(), true);
    let _ = std::net::TcpStream::connect(format!("{}:{}", ip, port));
}

async fn handle_request(
    ip: String,
    port: u16,
    request: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    logger::write_information("WireServer processing request.".to_string());

    let path: String = request.uri().path_and_query().unwrap().to_string();
    let path = path.trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    println!("handle_request: {}, {:?}", request.method(), path);
    println!("segments: {:?}", segments);

    if request.method() == "GET" {
        if !segments.is_empty() && segments[0] == "secure-channel" {
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
                        status.secureChannelState =
                            Some(key_keeper::MUST_SIG_WIRESERVER.to_string());
                    }
                }
                return Ok(Response::new(http::full_body(
                    serde_json::to_string(&status).unwrap().as_bytes().to_vec(),
                )));
            }
        } else if !segments.is_empty() && segments[0] == "machine?comp=goalstate" {
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
            return Ok(Response::new(http::full_body(
                goal_state_str.as_bytes().to_vec(),
            )));
        } else if path.starts_with("machine/") && path.contains("type=sharedConfig") {
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
            return Ok(Response::new(http::full_body(shared_config_str.as_bytes())));
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
            return Ok(Response::new(http::full_body(response_data.as_bytes())));
        }
    } else if request.method() == "POST" {
        if !segments.is_empty() && segments[0] == "secure-channel" {
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
                return Ok(Response::new(http::full_body(
                    serde_json::to_string(&key).unwrap().as_bytes().to_vec(),
                )));
            }
        } else if !segments.is_empty()
            && segments[0] == "machine"
            && segments.len() > 1
            && segments[1] == "?comp=telemetrydata"
        {
            return Ok(Response::new(http::empty_body()));
        }
    }

    let mut not_found = Response::new(http::empty_body());
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    Ok(not_found)
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
