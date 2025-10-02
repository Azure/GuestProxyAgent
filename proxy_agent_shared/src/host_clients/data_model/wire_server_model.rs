use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Versions")]
pub struct Versions {
    #[serde(rename = "Preferred")]
    pub preferred: Preferred,

    #[serde(rename = "Supported")]
    pub supported: Supported,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Preferred {
    #[serde(rename = "Version")]
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Supported {
    #[serde(rename = "Version")]
    pub versions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "GoalState")]
pub struct GoalState {
    #[serde(rename = "Version")]
    pub version: Option<String>,

    #[serde(rename = "Incarnation")]
    pub incarnation: Option<u32>,

    #[serde(rename = "Machine")]
    pub machine: Option<Machine>,

    #[serde(rename = "Container")]
    pub container: Option<Container>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Machine {
    #[serde(rename = "ExpectedState")]
    pub expected_state: Option<String>,

    #[serde(rename = "StopRolesDeadlineHint")]
    pub stop_roles_deadline_hint: Option<u64>,

    #[serde(rename = "LBProbePorts")]
    pub lb_probe_ports: Option<LBProbePorts>,

    #[serde(rename = "ExpectHealthReport")]
    pub expect_health_report: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LBProbePorts {
    #[serde(rename = "Port")]
    pub port: Option<Vec<u16>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Container {
    #[serde(rename = "ContainerId")]
    pub container_id: Option<String>,

    #[serde(rename = "RoleInstanceList")]
    pub role_instance_list: Option<RoleInstanceList>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleInstanceList {
    #[serde(rename = "RoleInstance")]
    pub role_instance: Option<Vec<RoleInstance>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleInstance {
    #[serde(rename = "InstanceId")]
    pub instance_id: Option<String>,

    #[serde(rename = "State")]
    pub state: Option<String>,

    #[serde(rename = "Configuration")]
    pub configuration: Option<Configuration>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Configuration {
    #[serde(rename = "HostingEnvironmentConfig")]
    pub hosting_environment_config: Option<String>,

    #[serde(rename = "SharedConfig")]
    pub shared_config: Option<String>,

    #[serde(rename = "ExtensionsConfig")]
    pub extensions_config: Option<String>,

    #[serde(rename = "FullConfig")]
    pub full_config: Option<String>,

    #[serde(rename = "Certificates")]
    pub certificates: Option<String>,

    #[serde(rename = "ConfigName")]
    pub config_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename = "RDConfig")]
pub struct RDConfig {
    #[serde(rename = "@version")]
    pub version: Option<String>,

    #[serde(rename = "StoredCertificates")]
    pub stored_certificates: Option<StoredCertificates>,

    #[serde(rename = "Deployment")]
    pub deployment: Option<Deployment>,

    #[serde(rename = "Incarnation")]
    pub incarnation: Option<Incarnation>,

    #[serde(rename = "Role")]
    pub role: Option<Role>,

    #[serde(rename = "HostingEnvironmentSettings")]
    pub hosting_environment_settings: Option<HostingEnvironmentSettings>,

    #[serde(rename = "ApplicationSettings")]
    pub application_settings: Option<ApplicationSettings>,

    #[serde(rename = "OutputEndpoints")]
    pub output_endpoints: Option<String>,

    #[serde(rename = "Instances")]
    pub instances: Option<Instances>,

    #[serde(rename = "Neighborhoods")]
    pub neighborhoods: Option<Neighborhoods>,
}

// ----- StoredCertificates -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StoredCertificates {
    #[serde(rename = "StoredCertificate", default)]
    pub stored_certificate: Vec<StoredCertificate>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StoredCertificate {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@certificateId")]
    pub certificate_id: Option<String>,
    #[serde(rename = "@storeName")]
    pub store_name: Option<String>,
    #[serde(rename = "@configurationLevel")]
    pub configuration_level: Option<String>,
}

// ----- Deployment -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Deployment {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@incarnation")]
    pub incarnation: Option<u32>,
    #[serde(rename = "@guid")]
    pub guid: Option<String>,

    #[serde(rename = "Service", default)]
    pub services: Vec<Service>,
    #[serde(rename = "ServiceInstance", default)]
    pub service_instances: Vec<ServiceInstance>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Service {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@guid")]
    pub guid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceInstance {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@guid")]
    pub guid: Option<String>,
}

// ----- Incarnation -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Incarnation {
    #[serde(rename = "@number")]
    pub number: Option<u32>,
    #[serde(rename = "@instance")]
    pub instance: Option<String>,
    #[serde(rename = "@guid")]
    pub guid: Option<String>,
}

// ----- Role -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Role {
    #[serde(rename = "@guid")]
    pub guid: Option<String>,
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@hostingEnvironment")]
    pub hosting_environment: Option<String>,
    #[serde(rename = "@hostingEnvironmentVersion")]
    pub hosting_environment_version: Option<u32>,
    #[serde(rename = "@software")]
    pub software: Option<String>,
    #[serde(rename = "@softwareType")]
    pub software_type: Option<String>,
    #[serde(rename = "@entryPoint")]
    pub entry_point: Option<String>,
    #[serde(rename = "@parameters")]
    pub parameters: Option<String>,
    #[serde(rename = "@cpu")]
    pub cpu: Option<u32>,
    #[serde(rename = "@memory")]
    pub memory: Option<u32>,
    #[serde(rename = "@bandwidth")]
    pub bandwidth: Option<u32>,
    #[serde(rename = "@isManagementRole")]
    pub is_management_role: Option<bool>,
}

// ----- HostingEnvironmentSettings -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct HostingEnvironmentSettings {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@Runtime")]
    pub runtime: Option<String>,
    #[serde(rename = "CAS")]
    pub cas: Option<CAS>,
    #[serde(rename = "PrivilegeLevel")]
    pub privilege_level: Option<PrivilegeLevel>,
    #[serde(rename = "AdditionalProperties")]
    pub additional_properties: Option<AdditionalProperties>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CAS {
    #[serde(rename = "@mode")]
    pub mode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PrivilegeLevel {
    #[serde(rename = "@mode")]
    pub mode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AdditionalProperties {
    #[serde(rename = "Extensions")]
    pub extensions: Option<String>, // CDATA content
}

// ----- ApplicationSettings -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ApplicationSettings {
    #[serde(rename = "Setting", default)]
    pub settings: Vec<Setting>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Setting {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@value")]
    pub value: Option<String>,
}

// ----- Instances -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Instances {
    #[serde(rename = "Instance", default)]
    pub instances: Vec<Instance>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Instance {
    #[serde(rename = "@id")]
    pub id: Option<String>,
    #[serde(rename = "@neighborhoodID")]
    pub neighborhood_id: Option<String>,
    #[serde(rename = "@address")]
    pub address: Option<String>,
    #[serde(rename = "FaultDomains")]
    pub fault_domains: Option<FaultDomains>,
    #[serde(rename = "InputEndpoints")]
    pub input_endpoints: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FaultDomains {
    #[serde(rename = "@randomID")]
    pub random_id: Option<u32>,
    #[serde(rename = "@updateID")]
    pub update_id: Option<u32>,
    #[serde(rename = "@updateCount")]
    pub update_count: Option<u32>,
}

// ----- Neighborhoods -----
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Neighborhoods {
    #[serde(rename = "Neighborhood", default)]
    pub neighborhoods: Vec<Neighborhood>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Neighborhood {
    #[serde(rename = "@id")]
    pub id: Option<String>,
    #[serde(rename = "@innerbandwidth")]
    pub innerbandwidth: Option<u32>,
    #[serde(rename = "@innerlatency")]
    pub innerlatency: Option<u32>,
    #[serde(rename = "@outwardbandwidth")]
    pub outwardbandwidth: Option<u32>,
    #[serde(rename = "@outwardlatency")]
    pub outwardlatency: Option<u32>,
    #[serde(rename = "@parentNeighborhoodID")]
    pub parent_neighborhood_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename = "HostingEnvironmentConfig")]
pub struct HostingEnvironmentConfig {
    #[serde(rename = "@version")]
    pub version: Option<String>,

    #[serde(rename = "@goalStateIncarnation")]
    pub goal_state_incarnation: Option<u32>,

    #[serde(rename = "StoredCertificates")]
    pub stored_certificates: Option<StoredCertificates>,

    #[serde(rename = "Deployment")]
    pub deployment: Option<Deployment>,

    #[serde(rename = "Incarnation")]
    pub incarnation: Option<Incarnation>,

    #[serde(rename = "Role")]
    pub role: Option<Role>,

    #[serde(rename = "HostingEnvironmentSettings")]
    pub hosting_environment_settings: Option<HostingEnvironmentSettings>,

    #[serde(rename = "ApplicationSettings")]
    pub application_settings: Option<ApplicationSettings>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_deserialization_test() {
        let xml_data = r#"
        <Versions>
            <Preferred>
                <Version>2015-04-05</Version>
            </Preferred>
            <Supported>
                <Version>2015-04-05</Version>
                <Version>2012-11-30</Version>
                <Version>2012-09-15</Version>
                <Version>2012-05-15</Version>
                <Version>2011-12-31</Version>
                <Version>2011-10-15</Version>
                <Version>2011-08-31</Version>
                <Version>2011-04-07</Version>
                <Version>2010-12-15</Version>
                <Version>2010-28-10</Version>
            </Supported>
        </Versions>
        "#;

        let versions: Versions = quick_xml::de::from_str(xml_data).unwrap();
        assert_eq!(versions.preferred.version, "2015-04-05");
        assert_eq!(versions.supported.versions.len(), 10);
    }

    #[test]
    fn goal_state_deserialization_test() {
        let xml_data = r#"
        <GoalState>
            <Version>2015-04-05</Version>
            <Incarnation>1</Incarnation>
            <Machine>
                <ExpectedState>Started</ExpectedState>
                <StopRolesDeadlineHint>300000</StopRolesDeadlineHint>
                <LBProbePorts>
                    <Port>16001</Port>
                </LBProbePorts>
                <ExpectHealthReport>FALSE</ExpectHealthReport>
            </Machine>
            <Container>
                <ContainerId>c9514be2-ff0a-4dee-a059-45a0452268e7</ContainerId>
                <RoleInstanceList>
                    <RoleInstance>
                        <InstanceId>896a1f5d-459b-4e58-a337-d113f9e97d25.instance</InstanceId>
                        <State>Started</State>
                        <Configuration>
                            <HostingEnvironmentConfig>HostingEnvironmentConfig_uri</HostingEnvironmentConfig>
                            <SharedConfig>SharedConfig_uri</SharedConfig>
                            <ExtensionsConfig>ExtensionsConfig_uri</ExtensionsConfig>
                            <FullConfig>FullConfig_uri</FullConfig>
                            <Certificates>Certificates_uri</Certificates>
                            <ConfigName>ConfigName.xml</ConfigName>
                        </Configuration>
                    </RoleInstance>
                </RoleInstanceList>
            </Container>
        </GoalState>
        "#;
        let goal_state: GoalState = quick_xml::de::from_str(xml_data).unwrap();
        assert_eq!(goal_state.version.unwrap(), "2015-04-05");
        assert_eq!(goal_state.incarnation.unwrap(), 1);

        let role_instances = goal_state
            .container
            .unwrap()
            .role_instance_list
            .unwrap()
            .role_instance
            .unwrap();
        assert_eq!(role_instances.len(), 1);
        let role_instance = &role_instances[0];
        assert_eq!(
            role_instance.instance_id.as_ref().unwrap(),
            "896a1f5d-459b-4e58-a337-d113f9e97d25.instance"
        );
        let configuration = role_instance.configuration.as_ref().unwrap();
        assert_eq!(
            configuration.full_config.as_ref().unwrap(),
            "FullConfig_uri"
        );
        assert_eq!(
            configuration.certificates.as_ref().unwrap(),
            "Certificates_uri"
        );
    }

    #[test]
    fn full_config_deserialization_test() {
        let xml_data = r#"
        <RDConfig version="1.0.0.0">
            <StoredCertificates>
                <StoredCertificate name="TenantEncryptionCert" certificateId="sha1:45750FFF384A47DEC65C9C7BB829B27E0562726F" storeName="My" configurationLevel="System"/>
            </StoredCertificates>
            <Deployment name="896a1f5d-459b-4e58-a337-d113f9e97d25" incarnation="0" guid="{0000000-0000000000-000000}">
                <Service name="service_name" guid="{00000000-0000-0000-0000-000000000000}"/>
                <ServiceInstance name="896a1f5d-459b-4e58-a337-d113f9e97d25.0" guid="{000000-000000000-000000}"/>
            </Deployment>
            <Incarnation number="1" instance="instance_test" guid="{000000000-000-00000}"/>
            <Role guid="{ad99c9e8-1821-8b8c-81a9-4653d9ba2980}" name="instance_test" hostingEnvironment="full" hostingEnvironmentVersion="0" software="" softwareType="ApplicationPackage" entryPoint="" parameters="" cpu="0" memory="0" bandwidth="0" isManagementRole="false"/>
            <HostingEnvironmentSettings name="full" Runtime="Deprecated_0.0.0.0.zip">
                <CAS mode="full"/>
                <PrivilegeLevel mode="max"/>
            </HostingEnvironmentSettings>
            <ApplicationSettings>
                <Setting name="ProvisionCertificate|TenantEncryptionCert" value="sha1:45750FFF384A47DEC65C9C7BB829B27E0562726F"/>
            </ApplicationSettings>
            <OutputEndpoints/>
            <Instances>
                <Instance id="instance_test" neighborhoodID="0000-00000000-000000" address="10.0.0.4">
                    <FaultDomains randomID="0" updateID="0" updateCount="0"/>
                    <InputEndpoints/>
                </Instance>
            </Instances>
        </RDConfig>
        "#;
        let rd_config: RDConfig = quick_xml::de::from_str(xml_data).unwrap();
        assert_eq!(rd_config.version.unwrap(), "1.0.0.0");
        assert_eq!(
            rd_config
                .stored_certificates
                .as_ref()
                .unwrap()
                .stored_certificate
                .len(),
            1
        );

        let certificate = &rd_config
            .stored_certificates
            .as_ref()
            .unwrap()
            .stored_certificate[0];
        assert_eq!(certificate.name.as_ref().unwrap(), "TenantEncryptionCert");
        assert_eq!(
            certificate.certificate_id.as_ref().unwrap(),
            "sha1:45750FFF384A47DEC65C9C7BB829B27E0562726F"
        );
    }
}
