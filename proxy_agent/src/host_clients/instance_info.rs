// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
pub struct InstanceInfo {
    compute: ComputeInfo,
}

#[derive(Deserialize, Serialize)]
#[allow(non_snake_case)]
struct ComputeInfo {
    location: String,
    name: String,
    resourceGroupName: String,
    subscriptionId: String,
    vmId: String,
    vmSize: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    offer: Option<String>,
}

impl InstanceInfo {
    pub fn get_subscription_id(&self) -> String {
        self.compute.subscriptionId.to_string()
    }

    pub fn get_vm_id(&self) -> String {
        self.compute.vmId.to_string()
    }

    pub fn get_resource_group_name(&self) -> String {
        self.compute.resourceGroupName.to_string()
    }

    pub fn get_image_origin(&self) -> u64 {
        let image_origin: u64;
        match &self.compute.offer {
            Some(offer) => {
                if offer == "" {
                    image_origin = 0; // custom
                } else {
                    image_origin = 1; // platform
                }
            }
            None => {
                image_origin = 0; // custom
            }
        }

        image_origin
    }
}

#[cfg(test)]
mod tests {
    use super::InstanceInfo;

    #[test]
    fn compute_instance_test() {
        let instance_string = r#"{
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

        let instace_info = serde_json::from_str::<InstanceInfo>(instance_string).unwrap();
        assert_eq!(
            "xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx",
            instace_info.get_subscription_id(),
            "subscription_id mismatch"
        );
        assert_eq!(
            "02aab8a4-74ef-476e-8182-f6d2ba4166a6",
            instace_info.get_vm_id(),
            "vm id mismatch"
        );
        assert_eq!(
            "macikgo-test-may-23",
            instace_info.get_resource_group_name(),
            "resource_group_name mismatch"
        );
        assert_eq!(1, instace_info.get_image_origin(), "image_origin mismatch");
    }
}
