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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_deserialization_test() {
        let certificates_json = r#"
        {
            "activityId": "11111111-1111111-11111111111-111111",
            "correlationId": "80e22e3b-3f9a-424e-b300-6cda2dd7e718",
            "certificates": [
            {
                "name": "TenantEncryptionCert",
                "storeName": "My",
                "configurationLevel": "System",
                "certificateInBase64": "certificateInBase64_test",
                "includePrivateKey": false,
                "thumbprint": "thumbprint_test",
                "certificateBlobFormatType": "PfxInClear"
            }
            ]
        }
        "#;
        let certificates: Certificates = serde_json::from_str(certificates_json).unwrap();
        assert_eq!(
            certificates.activity_id.unwrap(),
            "11111111-1111111-11111111111-111111"
        );
        assert_eq!(
            certificates.correlation_id.unwrap(),
            "80e22e3b-3f9a-424e-b300-6cda2dd7e718"
        );
        assert_eq!(certificates.certificates.as_ref().unwrap().len(), 1);
        assert_eq!(
            certificates.certificates.as_ref().unwrap()[0]
                .certificate_in_base64
                .as_ref()
                .unwrap(),
            "certificateInBase64_test"
        );
        assert_eq!(
            certificates.certificates.as_ref().unwrap()[0]
                .thumbprint
                .as_ref()
                .unwrap(),
            "thumbprint_test"
        );
    }

    #[test]
    fn vmsettings_deserialization_test() {
        let vmsettings_json = r#"
        {
            "hostGAPluginVersion": "1.0.8.179",
            "activityId": "1111-11111111-1111-11-1111",
            "correlationId": "000000-00000000-000000-0000",
            "inSvdSeqNo": 1,
            "certificatesRevision": 0,
            "extensionsLastModifiedTickCount": 638931417044754873,
            "extensionGoalStatesSource": "FastTrack",
            "statusUploadBlob": {
            "statusBlobType": "PageBlob",
            "value": "string"
            },
            "gaFamilies": [
            {
                "name": "Win7",
                "version": "2.7.41491.1176",
                "isVersionFromRSM": false,
                "isVMEnabledForRSMUpgrades": true,
                "uris": [
                "uri"
                ]
            },
            {
                "name": "Win8",
                "version": "2.7.41491.1176",
                "isVersionFromRSM": false,
                "isVMEnabledForRSMUpgrades": true,
                "uris": [
                "uri"
                ]
            }
            ],
            "extensionGoalStates": [
            {
                "name": "test",
                "version": "1.0.1",
                "location": "location",
                "failoverLocation": "location",
                "additionalLocations": [
                "location"
                ],
                "state": "enabled",
                "autoUpgrade": true,
                "runAsStartupTask": false,
                "isJson": true,
                "useExactVersion": true,
                "settingsSeqNo": 0,
                "isMultiConfig": false,
                "settings": [
                {
                    "protectedSettingsCertThumbprint": null,
                    "protectedSettings": null,
                    "publicSettings": "{}"
                }
                ]
            }
            ]
        }"#;

        let vmsettings: VMSettings = serde_json::from_str(vmsettings_json).unwrap();
        assert_eq!(vmsettings.host_ga_plugin_version.unwrap(), "1.0.8.179");
        assert_eq!(
            vmsettings.activity_id.unwrap(),
            "1111-11111111-1111-11-1111"
        );
        assert_eq!(
            vmsettings.correlation_id.unwrap(),
            "000000-00000000-000000-0000"
        );
        assert_eq!(vmsettings.in_svd_seq_no.unwrap(), 1);
        assert_eq!(vmsettings.certificates_revision.unwrap(), 0);
        assert_eq!(
            vmsettings.extensions_last_modified_tick_count.unwrap(),
            638931417044754873
        );
        assert_eq!(vmsettings.ga_families.as_ref().unwrap().len(), 2);
        assert_eq!(vmsettings.extension_goal_states.as_ref().unwrap().len(), 1);
    }
}
