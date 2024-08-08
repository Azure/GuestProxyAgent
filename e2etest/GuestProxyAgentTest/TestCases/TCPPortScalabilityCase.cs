// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;

namespace GuestProxyAgentTest.TestCases
{
    public class TCPPortScalabilityCase : TestCaseBase
    {
        public TCPPortScalabilityCase(bool imdsSecureChannelEnabled) : base("TCPPortScalabilityCase")
        {
            ImdsSecureChannelEnabled = imdsSecureChannelEnabled;
        }

        private bool ImdsSecureChannelEnabled { get; set; }

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
            List<(string, string)> parameterList = new List<(string, string)>();
            parameterList.Add(("imdsSecureChannelEnabled", ImdsSecureChannelEnabled.ToString()));
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, "IMDSPingTest.ps1", parameterList, false)).ToTestResultDetails(ConsoleLog);
        }
    }
}
