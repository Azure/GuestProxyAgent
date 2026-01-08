// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
using Azure.ResourceManager.Compute.Models;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;
using Newtonsoft.Json;
using System.Xml.Linq;

namespace GuestProxyAgentTest.TestCases
{
    internal class EnableProxyAgentCase : TestCaseBase
    {
        public EnableProxyAgentCase() : this("EnableProxyAgentCase", true, false)
        { }
        public EnableProxyAgentCase(string testCaseName) : this(testCaseName, true, false)
        { }

        public EnableProxyAgentCase(string testCaseName, bool enableProxyAgent, bool addProxyAgentExtensionForLinuxVM) : base(testCaseName)
        {
            EnableProxyAgent = enableProxyAgent;
            AddProxyAgentVMExtension = addProxyAgentExtensionForLinuxVM;
        }

        internal bool EnableProxyAgent { get; set; }

        internal bool AddProxyAgentVMExtension { get; set; } = false;

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            var vmr = context.VirtualMachineResource;

            var patch = new VirtualMachinePatch()
            {
                SecurityProfile = new SecurityProfile
                {
                    ProxyAgentSettings = new ProxyAgentSettings
                    {
                        Enabled = EnableProxyAgent
                    }
                }
            };
            // Only Linux VMs support flag 'AddProxyAgentExtension',
            // Windows VMs always have the GPA VM Extension installed when ProxyAgentSettings.Enabled is true.
            if (!Constants.IS_WINDOWS())
            {
                patch.SecurityProfile.ProxyAgentSettings.AddProxyAgentExtension = AddProxyAgentVMExtension;
            }

            if (EnableProxyAgent)
            {
                patch.SecurityProfile.ProxyAgentSettings.WireServer = new HostEndpointSettings
                {
                    InVmAccessControlProfileReferenceId = TestSetting.Instance.InVmWireServerAccessControlProfileReferenceId,
                    Mode = HostEndpointSettingsMode.Enforce
                };
                patch.SecurityProfile.ProxyAgentSettings.Imds = new HostEndpointSettings
                {
                    InVmAccessControlProfileReferenceId = TestSetting.Instance.InVmIMDSAccessControlProfileReferenceId,
                    Mode = HostEndpointSettingsMode.Audit
                };
            }

            await vmr.UpdateAsync(Azure.WaitUntil.Completed, patch, cancellationToken: context.CancellationToken);
            var iv = await vmr.InstanceViewAsync();
            context.TestResultDetails = new TestCaseResultDetails
            {
                CustomOut = JsonConvert.SerializeObject(iv),
                StdOut = "Enable ProxyAgent succeed.",
                StdErr = "",
                Succeed = true,
                FromBlob = false,
            };

        }

    }
}
