// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using Azure.ResourceManager.Compute.Models;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Resources;
using Azure.ResourceManager;
using Azure;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using GuestProxyAgentTest.Settings;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// Class for Build an Azure VM based on the test case setting
    /// </summary>
    class VMBuilder
    {
        private TestScenarioSetting testScenarioSetting = null!;
        private string vmName = "";
        private string vNetName = "";
        private string netInfName = "";
        private string pubIpName = "";
        private string rgName = "";
        private string adminUsername = "testuser";
        private string adminPassword = SdkContext.RandomResourceName("pP@1", 15);

        public VMBuilder() { }

        /// <summary>
        /// Load the test case setting, that set up the virtual machine related resource names, including virtual machine name, virtual network name, network interface name, public ip address name
        /// </summary>
        /// <param name="testScenarioSetting"></param>
        /// <returns></returns>
        public VMBuilder LoadTestCaseSetting(TestScenarioSetting testScenarioSetting)
        {
            this.testScenarioSetting = testScenarioSetting;
            this.rgName = this.testScenarioSetting.ResourceGroupName;
            var prefix = "e2e" + new Random().Next(1000);
            this.vmName = prefix + "vm";
            this.vNetName = prefix + "vNet";
            this.netInfName = prefix + "nInf";
            this.pubIpName = prefix + "pubIp";
            return this;
        }

        /// <summary>
        /// Build Build and return the VirtualMachine based on the setting
        /// </summary>
        /// <returns></returns>
        public async Task<VirtualMachineResource> Build(bool EnableProxyAgent)
        {
            PreCheck();
            ArmClient client = new(new GuestProxyAgentE2ETokenCredential(), defaultSubscriptionId: TestSetting.Instance.subscriptionId);

            var sub = await client.GetDefaultSubscriptionAsync();
            var rgs = sub.GetResourceGroups();
            if (await rgs.ExistsAsync(rgName))
            {
                Console.WriteLine($"Resource group: {rgName} already exists, cleaning it up.");
                await (await rgs.GetAsync(rgName)).Value.DeleteAsync(WaitUntil.Completed);
            }
            Console.WriteLine("Creating resource group: " + rgName);
            var rgData = new ResourceGroupData(TestSetting.Instance.location);
            rgData.Tags.Add(Constants.COULD_CLEANUP_TAG_NAME, "true");
            var rgr = rgs.CreateOrUpdate(WaitUntil.Completed, rgName, rgData).Value;

            VirtualMachineCollection vmCollection = rgr.GetVirtualMachines();
            Console.WriteLine("Creating virtual machine...");
            var vmr = (await vmCollection.CreateOrUpdateAsync(WaitUntil.Completed, this.vmName, await DoCreateVMData(rgr, EnableProxyAgent))).Value;
            Console.WriteLine("Virtual machine created, with id: " + vmr.Id);
            return vmr;
        }

        private async Task<VirtualMachineData> DoCreateVMData(ResourceGroupResource rgr, bool EnableProxyAgent)
        {
            var vmData = new VirtualMachineData(TestSetting.Instance.location)
            {
                HardwareProfile = new VirtualMachineHardwareProfile()
                {
                    VmSize = new VirtualMachineSizeType(TestSetting.Instance.vmSize),
                },
                StorageProfile = new VirtualMachineStorageProfile()
                {
                    ImageReference = new ImageReference()
                    {
                        Publisher = this.testScenarioSetting.VMImageDetails.Publisher,
                        Offer = this.testScenarioSetting.VMImageDetails.Offer,
                        Sku = this.testScenarioSetting.VMImageDetails.Sku,
                        Version = this.testScenarioSetting.VMImageDetails.Version,
                    },
                    OSDisk = new VirtualMachineOSDisk(DiskCreateOptionType.FromImage)
                    {
                        Name = "e2eVmOsDisk",
                        Caching = CachingType.ReadWrite,
                        ManagedDisk = new VirtualMachineManagedDisk()
                        {
                            StorageAccountType = StorageAccountType.StandardLrs,
                        },
                    },
                },
                OSProfile = new VirtualMachineOSProfile()
                {
                    ComputerName = vmName,
                    AdminUsername = this.adminUsername,
                    AdminPassword = this.adminPassword,
                },
                NetworkProfile = await DoCreateVMNetWorkProfile(rgr),
            };

            if (EnableProxyAgent)
            {
                vmData.SecurityProfile = new SecurityProfile()
                {
                    ProxyAgentSettings = new ProxyAgentSettings()
                    {
                        Enabled = true
                    }
                };
            }

            if (Constants.IS_WINDOWS())
            {
                vmData.OSProfile.WindowsConfiguration = new WindowsConfiguration()
                {
                    ProvisionVmAgent = true,
                    IsAutomaticUpdatesEnabled = true,
                    PatchSettings = new PatchSettings()
                    {
                        AssessmentMode = WindowsPatchAssessmentMode.ImageDefault,
                    },
                };
            }
            else
            {
                vmData.OSProfile.LinuxConfiguration = new LinuxConfiguration()
                {
                    //ProvisionVMAgent = true,
                    //IsPasswordAuthenticationDisabled = false,
                };
            }

            return vmData;
        }

        private async Task<VirtualMachineNetworkProfile> DoCreateVMNetWorkProfile(ResourceGroupResource rgr)
        {
            Console.WriteLine("Creating network profile");
            var vns = rgr.GetVirtualNetworks();
            await vns.CreateOrUpdateAsync(WaitUntil.Completed, this.vNetName, new VirtualNetworkData
            {
                AddressPrefixes =
                    {
                    "10.0.0.0/16"
                    },
                FlowTimeoutInMinutes = 10,
                Location = TestSetting.Instance.location,
                Subnets =
                {
                    new SubnetData
                    {
                        Name = "default",
                        AddressPrefix = "10.0.0.0/24",
                    }
                }
            });

            var pips = rgr.GetPublicIPAddresses();

            Console.WriteLine("Creating public ip address.");
            await pips.CreateOrUpdateAsync(WaitUntil.Completed, this.pubIpName, new PublicIPAddressData
            {
                Location = TestSetting.Instance.location
            });

            var nifs = rgr.GetNetworkInterfaces();

            Console.WriteLine("Creating network interface.");
            await nifs.CreateOrUpdateAsync(WaitUntil.Completed, this.netInfName, new NetworkInterfaceData()
            {
                IPConfigurations =
                    {
                        new NetworkInterfaceIPConfigurationData()
                        {
                            Subnet = new SubnetData()
                            {
                              Id = new ResourceIdentifier($"/subscriptions/{TestSetting.Instance.subscriptionId}/resourceGroups/{this.rgName}/providers/Microsoft.Network/virtualNetworks/{this.vNetName}/subnets/default"),
                            },
                            PublicIPAddress = new PublicIPAddressData()
                            {
                                Id = new ResourceIdentifier($"/subscriptions/{TestSetting.Instance.subscriptionId}/resourceGroups/{this.rgName}/providers/Microsoft.Network/publicIPAddresses/{this.pubIpName}"),
                            },
                            Name = "ipconfig1",
                        }
                    },
                Location = TestSetting.Instance.location,
            });

            return new VirtualMachineNetworkProfile()
            {
                NetworkInterfaces =
                    {
                        new VirtualMachineNetworkInterfaceReference()
                        {
                            Primary = true,
                            Id = new ResourceIdentifier($"/subscriptions/{TestSetting.Instance.subscriptionId}/resourceGroups/{this.rgName}/providers/Microsoft.Network/networkInterfaces/{this.netInfName}"),
                        }
                    },
            };
        }

        private void PreCheck()
        {
            if (this.testScenarioSetting == null)
            {
                throw new Exception("missing test case settings");
            }

            if (TestSetting.Instance == null)
            {
                throw new Exception("TestSetting not init.");
            }

            if (StorageHelper.Instance == null)
            {
                throw new Exception("StorageHelper not init.");
            }
        }
    }
}
