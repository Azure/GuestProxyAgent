// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;

namespace GuestProxyAgentTest.TestCases
{
    public class TCPPortScalabilityCase : TestCaseBase
    {
        public TCPPortScalabilityCase() : base("TCPPortScalabilityCase")
        {
        }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, "ConfigTCPPortScalability.ps1", null!, false)).ToTestResultDetails(ConsoleLog);
            if(!context.TestResultDetails.Succeed)
            {
                return;
            }
            // reboot 
            var vmr = context.VirtualMachineResource;
            await vmr.RestartAsync(Azure.WaitUntil.Completed);
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, "IMDSPingTest.ps1", null!, false)).ToTestResultDetails(ConsoleLog);
        }
    }
}
