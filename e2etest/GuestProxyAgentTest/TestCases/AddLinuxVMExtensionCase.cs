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

        private const string EXTENSION_NAME = "ProxyAgentLinuxTest";

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

            try
            {
                context.TestResultDetails = new GuestProxyAgentTest.Models.TestCaseResultDetails
                {
                    StdOut = "",
                    StdErr = "",
                    Succeed = false,
                    FromBlob = false,
                };

                var result = await vmr.GetVirtualMachineExtensions().CreateOrUpdateAsync(Azure.WaitUntil.Completed, EXTENSION_NAME, vmExtData);
                var provisioningState = result.Value.Data.ProvisioningState;
                if (result.HasValue && result.Value.Data != null && result.Value.Data.ProvisioningState == "Succeeded")
                {
                    context.TestResultDetails.Succeed = true;
                    context.TestResultDetails.CustomOut = FormatVMExtensionData(result.Value.Data);
                    return;
                }
            }
            catch (Exception ex)
            {
                // capture the exception into TestResultDetails and continue poll the extension instance view
                context.TestResultDetails.StdErr = ex.ToString();
            }

            // poll the extension isntance view for 5 minutes more
            var startTime = DateTime.UtcNow;
            while (true)
            {
                var vmExtension = await vmr.GetVirtualMachineExtensions().GetAsync(EXTENSION_NAME);
                var instanceView = vmExtension?.Value?.Data?.InstanceView;
                if (instanceView?.Statuses?.Count > 0 && instanceView.Statuses[0].DisplayStatus == "Provisioning succeeded")
                {
                    context.TestResultDetails.Succeed = true;
                    context.TestResultDetails.CustomOut = FormatVMExtensionData(vmExtension.Value.Data);
                    return;
                }

                if (DateTime.UtcNow - startTime > TimeSpan.FromMinutes(5))
                {
                    // poll timed out, report failure with the extension data
                    context.TestResultDetails.CustomOut = FormatVMExtensionData(vmExtension?.Value?.Data);
                    return;
                }

                // wait for 10 seconds before polling again
                await Task.Delay(10000);
            }
        }
    }
}