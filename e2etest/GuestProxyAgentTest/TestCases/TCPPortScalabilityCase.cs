// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;

namespace GuestProxyAgentTest.TestCases
{
    public class TCPPortScalabilityCase : TestCaseBase
    {
        public TCPPortScalabilityCase() : base("ConfigTCPPortScalability")
        { }

        private bool ImdsSecureChannelEnabled { get; set; }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, "ConfigTCPPortScalability.ps1", null!, false)).ToTestResultDetails(context.Logger);
        }
    }
}
