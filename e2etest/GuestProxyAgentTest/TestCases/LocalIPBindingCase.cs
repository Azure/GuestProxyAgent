// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;

namespace GuestProxyAgentTest.TestCases
{
    public class LocalIPBindingCase : TestCaseBase
    {
        public LocalIPBindingCase() : base("LocalIPBindingCase")
        {
        }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, "PingTestOnBindingLocalIP.ps1", null!, false)).ToTestResultDetails(ConsoleLog);
        }
    }
}
