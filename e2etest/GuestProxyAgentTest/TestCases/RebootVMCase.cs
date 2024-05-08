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
            var vmr = context.VirtualMachineResource;
            await vmr.RestartAsync(Azure.WaitUntil.Completed);
            var iv = await vmr.InstanceViewAsync();
            context.TestResultDetails = new TestCaseResultDetails
            {
                CustomOut = JsonConvert.SerializeObject(iv),
                StdOut = "Reboot VM case succeed.",
                StdErr = "",
                Succeed = true,
                FromBlob = false,
            };
        }
    }
}
