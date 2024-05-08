// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct GoalState {
    Version: String,
    Incarnation: u32,
    Machine: MachineField,
    Container: ContainerField,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct MachineField {
    ExpectedState: String,
    StopRolesDeadlineHint: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    LBProbePorts: Option<LbProbePortsField>,
    ExpectHealthReport: String,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct LbProbePortsField {
    #[serde(rename = "Port")]
    ports: Vec<u16>,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct ContainerField {
    ContainerId: String,
    #[serde(rename = "RoleInstanceList")]
    RoleInstanceList: RoleInstanceListField,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct RoleInstanceListField {
    #[serde(rename = "RoleInstance")]
    RoleInstance: Vec<RoleInstanceField>,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct RoleInstanceField {
    InstanceId: String,
    State: String,
    Configuration: RoleConfigField,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct RoleConfigField {
    HostingEnvironmentConfig: String,
    SharedConfig: String,
    ExtensionsConfig: String,
    FullConfig: String,
    Certificates: String,
    ConfigName: String,
}

impl GoalState {
    pub fn get_container_id(&self) -> String {
        self.Container.ContainerId.to_string()
    }

    pub fn get_shared_config_uri(&self) -> String {
        self.Container.RoleInstanceList.RoleInstance[0]
            .Configuration
            .SharedConfig.to_string()
    }
}

#[derive(Deserialize, Serialize, PartialEq)]
#[allow(non_snake_case)]
pub struct SharedConfig {
    Deployment: DeploymentField,
    Role: RoleField,
    Instances: InstancesField,
}

#[derive(Deserialize, Serialize, PartialEq)]
#[allow(non_snake_case)]
struct DeploymentField {
    name: String,
    guid: String,
    incarnation: String,
}

#[derive(Deserialize, Serialize, PartialEq)]
#[allow(non_snake_case)]
struct RoleField {
    guid: String,
    name: String,
}

#[derive(Deserialize, Serialize, PartialEq)]
struct InstancesField {
    #[serde(rename = "Instance")]
    instances: Vec<SharedConfigInstance>,
}

#[derive(Deserialize, Serialize, PartialEq)]
#[allow(non_snake_case)]
struct SharedConfigInstance {
    id: String,
    address: String,
}

impl SharedConfig {
    pub fn get_deployment_name(&self) -> String {
        self.Deployment.name.to_string()
    }

    pub fn get_role_name(&self) -> String {
        self.Role.name.to_string()
    }

    pub fn get_role_instance_name(&self) -> String {
        match self.Instances.instances.first() {
            Some(instance) => instance.id.to_string(),
            None => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::host_clients::goal_state::SharedConfig;

    use super::GoalState;

    #[test]
    fn goal_state_test() {
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
            <Package>http://168.63.129.16:80/machine/?comp=package&amp;incarnation=Win8-Win8_2.7.32211.3_221108-1339_GuestAgentPackage_NoWER.zip</Package>
            <PackageIncarnation>Win8-Win8_2.7.32211.3_221108-1339_GuestAgentPackage_NoWER.zip</PackageIncarnation>
          </Machine>
          <Container>
            <ContainerId>374188df-b0a2-456a-a7b2-83f28b18d36f</ContainerId>
            <RoleInstanceList>
              <RoleInstance>
                <InstanceId>7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker_IN_0</InstanceId>
                <State>Started</State>
                <Configuration>
                  <HostingEnvironmentConfig>http://168.63.129.16:80/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=hostingEnvironmentConfig&amp;incarnation=16</HostingEnvironmentConfig>
                  <SharedConfig>http://168.63.129.16:80/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=sharedConfig&amp;incarnation=16</SharedConfig>
                  <ExtensionsConfig>http://168.63.129.16:80/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=extensionsConfig&amp;incarnation=16</ExtensionsConfig>
                  <FullConfig>http://168.63.129.16:80/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&amp;type=fullConfig&amp;incarnation=16</FullConfig>
                  <Certificates>http://168.63.129.16:80/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=certificates&amp;incarnation=16</Certificates>
                  <ConfigName>7d2798bb72a0413d9a60b355277df726.132.7d2798bb72a0413d9a60b355277df726.78.TenantAdminApi.Worker_IN_0.1.xml</ConfigName>
                </Configuration>
              </RoleInstance>
            </RoleInstanceList>
          </Container>
        </GoalState>"#;

        let goal_state = serde_xml_rs::from_str::<GoalState>(goal_state_str).unwrap();
        assert_eq!(
            "374188df-b0a2-456a-a7b2-83f28b18d36f",
            goal_state.get_container_id(),
            "ContainerId mismatch"
        );
        assert_eq!("http://168.63.129.16:80/machine/374188df-b0a2-456a-a7b2-83f28b18d36f/7d2798bb72a0413d9a60b355277df726.TenantAdminApi.Worker%5FIN%5F0?comp=config&type=sharedConfig&incarnation=16", goal_state.get_shared_config_uri(), "SharedConfig mismatch");
    }

    #[test]
    fn shared_config_test() {
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

        let shared_config = serde_xml_rs::from_str::<SharedConfig>(shared_config_str).unwrap();
        assert_eq!(
            "7d2798bb72a0413d9a60b355277df726",
            shared_config.get_deployment_name(),
            "deployment_name mismatch"
        );
        assert_eq!(
            "TenantAdminApi.Worker",
            shared_config.get_role_name(),
            "role_name mismatch"
        );
        assert_eq!(
            "TenantAdminApi.Worker_IN_0",
            shared_config.get_role_instance_name(),
            "role_instance_name mismatch"
        );
    }
}
