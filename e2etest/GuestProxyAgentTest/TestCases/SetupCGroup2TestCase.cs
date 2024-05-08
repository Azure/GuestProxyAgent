// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestCases
{
    public class SetupCGroup2TestCase : TestCaseBase
    {
        public SetupCGroup2TestCase(string testCaseName) : base(testCaseName)
        {

        }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, Constants.SETUP_CGROUP2_SCRIPT_NAME, null!, false)).ToTestResultDetails();
        }
    }
}
