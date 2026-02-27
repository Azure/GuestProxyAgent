// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using Azure.ResourceManager.Network;
using Azure.ResourceManager.Resources;
using GuestProxyAgentTest.Settings;
using System.Linq;

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
        private string adminPassword = new ResourceNamer("").RandomName("pP@1", 15);

        // In order to use the plan, we need to accept the terms first.
        // https://learn.microsoft.com/en-us/cli/azure/vm/image/terms?view=azure-cli-latest#az-vm-image-terms-accept
        // az vm image terms accept --urn almalinux:almalinux:9:latest --subscription <subscriptionId>
        // az vm image terms accept --urn kinvolk:flatcar:stable:latest --subscription <subscriptionId>
        // az vm image terms accept --urn resf:rockylinux-x86_64:9-base:latest --subscription <subscriptionId>
        private readonly string[] PLAN_REQUIRED_IMAGES = new string[] { "almalinux", "kinvolk", "resf" };

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
        // Preferred fallback VM sizes in order of preference, grouped by architecture.
        private static readonly string[] FALLBACK_VM_SIZES_X64 = new string[]
        {
            "Standard_D2as_v5"
        };

        private static readonly string[] FALLBACK_VM_SIZES_ARM64 = new string[]
        {
            "Standard_B2pls_v5",
        };

        public async Task<VirtualMachineResource> Build(bool enableProxyAgent, CancellationToken cancellationToken)
        {
            PreCheck();
            ArmClient client = new(new GuestProxyAgentE2ETokenCredential(), defaultSubscriptionId: TestSetting.Instance.subscriptionId);

            var sub = await client.GetDefaultSubscriptionAsync();

            // Resolve an available VM size before creating resources
            var resolvedVmSize = await GetAvailableVmSizeAsync(sub);
            Console.WriteLine($"Resolved VM size: {resolvedVmSize}");

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
            var vmr = (await vmCollection.CreateOrUpdateAsync(WaitUntil.Completed, this.vmName, await DoCreateVMData(rgr, enableProxyAgent, resolvedVmSize), cancellationToken: cancellationToken)).Value;
            Console.WriteLine("Virtual machine created, with id: " + vmr.Id);
            return vmr;
        }

        /// <summary>
        /// Check if the configured VM size is available in the target location.
        /// If not, try fallback sizes. Returns the first available VM size.
        /// </summary>
        private async Task<string> GetAvailableVmSizeAsync(SubscriptionResource sub)
        {
            // Collect available VM SKUs with their vCPU count and architecture
            var availableSkus = new List<(string Name, int VCpus, string Architecture)>();
            await foreach (var sku in sub.GetComputeResourceSkusAsync(filter: $"location eq '{TestSetting.Instance.location}'"))
            {
                if (sku.ResourceType != null
                    && string.Equals(sku.ResourceType, "virtualMachines", StringComparison.OrdinalIgnoreCase)
                    && !sku.Restrictions.Any(r => r.ReasonCode == ComputeResourceSkuRestrictionsReasonCode.NotAvailableForSubscription))
                {
                    var vCpuCap = sku.Capabilities.FirstOrDefault(c => string.Equals(c.Name, "vCPUs", StringComparison.OrdinalIgnoreCase));
                    int vCpus = vCpuCap != null && int.TryParse(vCpuCap.Value, out var v) ? v : 0;

                    var archCap = sku.Capabilities.FirstOrDefault(c => string.Equals(c.Name, "CpuArchitectureType", StringComparison.OrdinalIgnoreCase));
                    string arch = archCap?.Value ?? "x64";

                    availableSkus.Add((sku.Name, vCpus, arch));
                }
            }

            var availableNames = new HashSet<string>(availableSkus.Select(s => s.Name), StringComparer.OrdinalIgnoreCase);
            bool isArm64 = this.testScenarioSetting.VMImageDetails.IsArm64;
            string requiredArch = isArm64 ? "Arm64" : "x64";

            var configuredSize = TestSetting.Instance.vmSize;
            if (availableNames.Contains(configuredSize))
            {
                Console.WriteLine($"Configured VM size '{configuredSize}' is available.");
                return configuredSize;
            }

            Console.WriteLine($"WARNING: Configured VM size '{configuredSize}' is not available in '{TestSetting.Instance.location}'. Searching for a fallback...");

            // First try the explicit fallback list
            var fallbacks = isArm64 ? FALLBACK_VM_SIZES_ARM64 : FALLBACK_VM_SIZES_X64;
            foreach (var fallback in fallbacks)
            {
                if (availableNames.Contains(fallback))
                {
                    Console.WriteLine($"Using fallback VM size: '{fallback}'");
                    return fallback;
                }
            }

            // If no explicit fallback is available, pick the first available 2 vCPU size matching the required architecture
            var autoSelected = availableSkus
                .Where(s => s.VCpus == 2 && string.Equals(s.Architecture, requiredArch, StringComparison.OrdinalIgnoreCase))
                .Select(s => s.Name)
                .FirstOrDefault();
            if (autoSelected != null)
            {
                Console.WriteLine($"Using auto-selected 2 vCPU {requiredArch} VM size: '{autoSelected}'");
                return autoSelected;
            }

            // If none of the preferred fallbacks are available, return the configured size and let Azure report the error.
            Console.WriteLine($"WARNING: No fallback VM size is available either. Proceeding with configured size '{configuredSize}'.");
            return configuredSize;
        }

        public async Task<VirtualMachineResource> GetVirtualMachineResource()
        {
            PreCheck();
            ArmClient client = new(new GuestProxyAgentE2ETokenCredential(), defaultSubscriptionId: TestSetting.Instance.subscriptionId);
            var sub = await client.GetDefaultSubscriptionAsync();
            return sub.GetResourceGroups().Get(this.rgName).Value.GetVirtualMachine(this.vmName);
        }

        private async Task<VirtualMachineData> DoCreateVMData(ResourceGroupResource rgr, bool enableProxyAgent, string vmSize)
        {
            var vmData = new VirtualMachineData(TestSetting.Instance.location)
            {
                HardwareProfile = new VirtualMachineHardwareProfile()
                {
                    VmSize = new VirtualMachineSizeType(vmSize),
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

            if (enableProxyAgent)
            {
                vmData.SecurityProfile = new SecurityProfile()
                {
                    ProxyAgentSettings = new ProxyAgentSettings()
                    {
                        Enabled = true,
                        WireServer = new HostEndpointSettings()
                        {
                            InVmAccessControlProfileReferenceId = TestSetting.Instance.InVmWireServerAccessControlProfileReferenceId,
                        },
                        Imds = new HostEndpointSettings()
                        {
                            InVmAccessControlProfileReferenceId = TestSetting.Instance.InVmIMDSAccessControlProfileReferenceId,
                        },
                    }
                };
                if (!Constants.IS_WINDOWS())
                {
                    // Only Linux VMs support flag 'AddProxyAgentExtension',
                    // Windows VMs always have the GPA VM Extension installed when ProxyAgentSettings.Enabled is true.
                    vmData.SecurityProfile.ProxyAgentSettings.AddProxyAgentExtension = true;
                }
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

            if (PLAN_REQUIRED_IMAGES.Contains(this.testScenarioSetting.VMImageDetails.Publisher))
            {
                vmData.Plan = new ComputePlan()
                {
                    Name = this.testScenarioSetting.VMImageDetails.Sku,
                    Publisher = this.testScenarioSetting.VMImageDetails.Publisher,
                    Product = this.testScenarioSetting.VMImageDetails.Offer,
                };
            }

            if (this.testScenarioSetting.VMImageDetails.IsArm64)
            {
                // workarounds to use ARM64 VM Extension
                vmData.Tags.Add(Constants.TAGS_ENFORCE_ARCHITECTURE_TYPE_FOR_EXTENSIONS, "true");
                vmData.Tags.Add(Constants.TAGS_MUST_NOT_REUSE_PREPROVISIONED_VM, "true");
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
                        DefaultOutboundAccess = false
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
