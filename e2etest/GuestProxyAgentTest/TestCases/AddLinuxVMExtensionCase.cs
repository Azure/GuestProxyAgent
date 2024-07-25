// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestScenarios;
using Azure.ResourceManager.Compute;

namespace GuestProxyAgentTest.TestCases
{
    /// <summary>
    /// Reboot VM test case
    /// </summary>
    public class AddLinuxVMExtensionCase : TestCaseBase
    {
        public AddLinuxVMExtensionCase() : base("AddLinuxVMExtensionCase")
        { }
        public AddLinuxVMExtensionCase(string testCaseName) : base(testCaseName)
        { 
        }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            var vmr = context.VirtualMachineResource;
            var vmExtData = new VirtualMachineExtensionData(GuestProxyAgentTest.Settings.TestSetting.Instance.location)
            {
                Location = GuestProxyAgentTest.Settings.TestSetting.Instance.location,
                Publisher = "Microsoft.CPlat.ProxyAgent",
                ExtensionType = "ProxyAgentLinuxTest",
                TypeHandlerVersion = "1.0",
                AutoUpgradeMinorVersion = false,
                EnableAutomaticUpgrade = false,
                Settings = 
                {
                }
            };
            var result = await vmr.GetVirtualMachineExtensions().CreateOrUpdateAsync(Azure.WaitUntil.Completed, "ProxyAgentLinuxTest", vmExtData);
            context.TestResultDetails = new GuestProxyAgentTest.Models.TestCaseResultDetails
            {
                CustomOut =  result.Value.Data.ToString(),
                StdOut = "",
                StdErr =  "",
                Succeed = result.Value.Data.ProvisioningState == "Succeeded",
                FromBlob = false,
            };
        }
    }
}
