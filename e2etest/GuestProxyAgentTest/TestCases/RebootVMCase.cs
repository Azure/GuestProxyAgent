// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.TestScenarios;
using Newtonsoft.Json;

namespace GuestProxyAgentTest.TestCases
{
    /// <summary>
    /// Reboot VM test case
    /// </summary>
    public class RebootVMCase : TestCaseBase
    {
        public RebootVMCase() : base("RebootVMCase")
        { }
        public RebootVMCase(string testCaseName) : base(testCaseName)
        { }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = new TestCaseResultDetails
            {
                StdOut = "",
                StdErr = "",
                Succeed = false,
                FromBlob = false,
            };

            var vmr = context.VirtualMachineResource;
            try
            {
                await vmr.RestartAsync(Azure.WaitUntil.Completed);
                var iv = await vmr.InstanceViewAsync();
                context.TestResultDetails = new TestCaseResultDetails
                {
                    CustomOut = JsonConvert.SerializeObject(iv),
                    StdOut = "Reboot VM case succeed.",
                    StdErr = "",
                    Succeed = true,
                };
                return;
            }
            catch (Exception ex)
            {
                // capture the exception into TestResultDetails and continue poll the vm instance view
                context.TestResultDetails.StdErr = ex.ToString();
            }

            // if the reboot operation failed, try check the VM instance view for 5 minutes
            var startTime = DateTime.UtcNow;
            while (true)
            {
                var instanceView = await vmr.InstanceViewAsync();
                if (instanceView?.Value?.Statuses?.Count > 0 && (instanceView.Value.Statuses[0].DisplayStatus == "Provisioning succeeded"
                    || instanceView.Value.Statuses[0].DisplayStatus == "VM running"))
                {
                    context.TestResultDetails.Succeed = true;
                    context.TestResultDetails.StdOut = "Reboot VM case succeed.";
                    context.TestResultDetails.CustomOut = JsonConvert.SerializeObject(instanceView);
                    return;
                }

                if (DateTime.UtcNow - startTime > TimeSpan.FromMinutes(5))
                {
                    // poll timed out, report failure with the extension data
                    context.TestResultDetails.CustomOut = JsonConvert.SerializeObject(instanceView);
                    return;
                }

                // wait for 10 seconds before polling again
                await Task.Delay(10000);
            }
        }
    }
}
