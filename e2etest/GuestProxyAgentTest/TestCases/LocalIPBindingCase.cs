// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;

namespace GuestProxyAgentTest.TestCases
{
    public class LocalIPBindingCase : TestCaseBase
    {
        public LocalIPBindingCase(bool imdsSecureChannelEnabled) : base("LocalIPBindingCase")
        {
            ImdsSecureChannelEnabled = imdsSecureChannelEnabled;
        }

        private bool ImdsSecureChannelEnabled { get; set; }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            List<(string, string)> parameterList = new List<(string, string)>();
            parameterList.Add(("imdsSecureChannelEnabled", ImdsSecureChannelEnabled.ToString()));
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, "PingTestOnBindingLocalIP.ps1", parameterList, false)).ToTestResultDetails(ConsoleLog);
        }
    }
}
