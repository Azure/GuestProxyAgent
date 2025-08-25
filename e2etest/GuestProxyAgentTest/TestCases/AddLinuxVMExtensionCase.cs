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
        { }

        private const string EXTENSION_NAME = "ProxyAgentLinuxTest";

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            var vmr = context.VirtualMachineResource;
            var vmExtData = new VirtualMachineExtensionData(GuestProxyAgentTest.Settings.TestSetting.Instance.location)
            {
                Location = GuestProxyAgentTest.Settings.TestSetting.Instance.location,
                Publisher = "Microsoft.CPlat.ProxyAgent",
                ExtensionType = context.ScenarioSetting.VMImageDetails.IsArm64 ? "ProxyAgentLinuxARM64Test" : "ProxyAgentLinuxTest",
                TypeHandlerVersion = "1.0",
                AutoUpgradeMinorVersion = false,
                EnableAutomaticUpgrade = false,
                Settings = { }
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

                var result = await vmr.GetVirtualMachineExtensions().CreateOrUpdateAsync(Azure.WaitUntil.Completed, EXTENSION_NAME, vmExtData, cancellationToken: context.CancellationToken);
                var provisioningState = result.Value.Data.ProvisioningState;
                if (result.HasValue && result.Value.Data != null && result.Value.Data.ProvisioningState == "Succeeded")
                {
                    // add vm extension operation succeeded
                    context.TestResultDetails.Succeed = true;
                    context.TestResultDetails.CustomOut = FormatVMExtensionData(result.Value.Data);
                    return;
                }
                else
                {
                    // capture the provisioning data into TestResultDetails and continue poll the extension instance view
                    context.TestResultDetails.StdErr = string.Format("VMExtension provisioning data: {}", FormatVMExtensionData(result?.Value?.Data));
                }
            }
            catch (Exception ex)
            {
                // capture the exception into TestResultDetails and continue poll the extension instance view
                context.TestResultDetails.StdErr = ex.ToString();
            }

            // poll the extension instance view for 5 minutes more
            var startTime = DateTime.UtcNow;
            while (true)
            {
                var vmExtension = await vmr.GetVirtualMachineExtensionAsync(EXTENSION_NAME, expand: "instanceView", cancellationToken: context.CancellationToken);
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