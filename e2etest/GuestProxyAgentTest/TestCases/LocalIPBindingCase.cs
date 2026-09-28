// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestCases
{
    public class LocalIPBindingCase : TestCaseBase
    {
        public LocalIPBindingCase() : base("LocalIPBindingCase")
        {
        }

        public LocalIPBindingCase(string testCaseName) : base(testCaseName)
        {
        }


        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            List<(string, string)> parameterList = new List<(string, string)>();
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, Constants.PING_TEST_ON_BINDING_LOCAL_IP_SCRIPT_NAME, parameterList, false)).ToTestResultDetails(context.Logger);
        }
    }
}
