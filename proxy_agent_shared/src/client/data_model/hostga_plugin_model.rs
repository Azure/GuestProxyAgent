use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct VMSettings {
    #[serde(rename = "hostGAPluginVersion")]
    pub host_ga_plugin_version: Option<String>,
    #[serde(rename = "activityId")]
    pub activity_id: Option<String>,
    #[serde(rename = "correlationId")]
    pub correlation_id: Option<String>,
    #[serde(rename = "inSvdSeqNo")]
    pub in_svd_seq_no: Option<u64>,
    #[serde(rename = "certificatesRevision")]
    pub certificates_revision: Option<u64>,
    #[serde(rename = "extensionsLastModifiedTickCount")]
    pub extensions_last_modified_tick_count: Option<u64>,
    #[serde(rename = "extensionGoalStatesSource")]
    pub extension_goal_states_source: Option<String>,
    #[serde(rename = "statusUploadBlob")]
    pub status_upload_blob: Option<StatusUploadBlob>,
    #[serde(rename = "gaFamilies")]
    pub ga_families: Option<Vec<GaFamily>>,
    #[serde(rename = "extensionGoalStates")]
    pub extension_goal_states: Option<Vec<ExtensionGoalState>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusUploadBlob {
    #[serde(rename = "statusBlobType")]
    pub status_blob_type: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GaFamily {
    pub name: Option<String>,
    pub version: Option<String>,
    #[serde(rename = "isVersionFromRSM")]
    pub is_version_from_rsm: Option<bool>,
    #[serde(rename = "isVMEnabledForRSMUpgrades")]
    pub is_vm_enabled_for_rsm_upgrades: Option<bool>,
    pub uris: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtensionGoalState {
    pub name: Option<String>,
    pub version: Option<String>,
    pub location: Option<String>,
    #[serde(rename = "failoverLocation")]
    pub failover_location: Option<String>,
    #[serde(rename = "additionalLocations")]
    pub additional_locations: Option<Vec<String>>,
    pub state: Option<String>,
    #[serde(rename = "autoUpgrade")]
    pub auto_upgrade: Option<bool>,
    #[serde(rename = "runAsStartupTask")]
    pub run_as_startup_task: Option<bool>,
    #[serde(rename = "isJson")]
    pub is_json: Option<bool>,
    #[serde(rename = "useExactVersion")]
    pub use_exact_version: Option<bool>,
    #[serde(rename = "settingsSeqNo")]
    pub settings_seq_no: Option<u64>,
    #[serde(rename = "isMultiConfig")]
    pub is_multi_config: Option<bool>,
    pub settings: Option<Vec<Settings>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    #[serde(rename = "protectedSettingsCertThumbprint")]
    pub protected_settings_cert_thumbprint: Option<String>,
    #[serde(rename = "protectedSettings")]
    pub protected_settings: Option<String>,
    #[serde(rename = "publicSettings")]
    pub public_settings: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawCertificatesPayload {
    #[serde(rename = "Pkcs7BlobWithPfxContents")]
    pub pkcs7_blob_with_pfx_contents: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Certificates {
    #[serde(rename = "activityId")]
    pub activity_id: Option<String>,

    #[serde(rename = "correlationId")]
    pub correlation_id: Option<String>,
    #[serde(rename = "certificates")]
    pub certificates: Option<Vec<Certificate>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Certificate {
    #[serde(rename = "name")]
    pub name: Option<String>,

    #[serde(rename = "storeName")]
    pub store_name: Option<String>,

    #[serde(rename = "configurationLevel")]
    pub configuration_level: Option<String>,

    #[serde(rename = "certificateInBase64")]
    pub certificate_in_base64: Option<String>,

    #[serde(rename = "includePrivateKey")]
    pub include_private_key: Option<bool>,

    #[serde(rename = "thumbprint")]
    pub thumbprint: Option<String>,

    #[serde(rename = "certificateBlobFormatType")]
    pub certificate_blob_format_type: Option<String>,
}
