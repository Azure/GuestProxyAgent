// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestCases
{
    public class IMDSPingTestCase : TestCaseBase
    {
        public IMDSPingTestCase(string testCaseName) : base(testCaseName)
        {

        }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, Constants.IMDS_PING_TEST_SCRIPT_NAME, null!, false)).ToTestResultDetails(ConsoleLog);
        }
    }
}
