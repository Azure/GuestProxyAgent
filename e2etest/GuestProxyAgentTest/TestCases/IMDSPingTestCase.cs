// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestCases
{
    public class IMDSPingTestCase : TestCaseBase
    {
        public IMDSPingTestCase(string testCaseName, bool imdsSecureChannelEnabled, bool ipv6DualStackSupported = true) : base(testCaseName)
        {
            ImdsSecureChannelEnabled = imdsSecureChannelEnabled;
            Ipv6DualStackSupported = ipv6DualStackSupported;
        }

        private bool ImdsSecureChannelEnabled { get; set; }
        private bool Ipv6DualStackSupported { get; set; }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            List<(string, string)> parameterList = new List<(string, string)>();
            parameterList.Add(("imdsSecureChannelEnabled", ImdsSecureChannelEnabled.ToString()));
            parameterList.Add(("ipv6DualStackSupported", Ipv6DualStackSupported.ToString()));
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, Constants.IMDS_PING_TEST_SCRIPT_NAME, parameterList, false)).ToTestResultDetails(context.Logger);
        }
    }
}
