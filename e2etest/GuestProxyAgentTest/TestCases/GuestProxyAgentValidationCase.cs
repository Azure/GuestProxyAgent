// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;
using Newtonsoft.Json;

namespace GuestProxyAgentTest.TestCases
{
    /// <summary>
    /// Hello test on In VM script test case
    /// </summary>
    public class GuestProxyAgentValidationCase : TestCaseBase
    {

        private static readonly string EXPECTEDGUESTPROXYAGENTSERVICESTATUS;
        static GuestProxyAgentValidationCase()
        {
            if (Constants.IS_WINDOWS())
            {
                EXPECTEDGUESTPROXYAGENTSERVICESTATUS = "Running";
            }
            else
            {
                EXPECTEDGUESTPROXYAGENTSERVICESTATUS = "enabled";
            }
        }
        public GuestProxyAgentValidationCase() : base("GuestProxyAgentValidationCase")
        { }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, Constants.GUEST_PROXY_AGENT_VALIDATION_SCRIPT_NAME, null!)).ToTestResultDetails(ConsoleLog);
            if (context.TestResultDetails.Succeed && context.TestResultDetails.CustomOut != null)
            {
                var validationDetails = context.TestResultDetails.SafeDeserializedCustomOutAs<GuestProxyAgentValidationDetails>();
                // check the validation json output, if the guest proxy agent serice was installed and runing and guest proxy agent process exists and log was generate,
                // then consider it as succeed, otherwise fail the case.
                if (validationDetails != null
                    && validationDetails.GuestProxyAgentServiceInstalled
                    && validationDetails.GuestProxyAgentServiceStatus.Equals(EXPECTEDGUESTPROXYAGENTSERVICESTATUS, StringComparison.OrdinalIgnoreCase)
                    && validationDetails.GuestProxyProcessStarted
                    && validationDetails.GuestProxyAgentLogGenerated)
                {
                    context.TestResultDetails.Succeed = true;
                }
                else
                {
                    context.TestResultDetails.Succeed = false;
                }
            }
        }
    }

    class GuestProxyAgentValidationDetails
    {
        public bool GuestProxyAgentServiceInstalled { get; set; }
        public bool GuestProxyProcessStarted { get; set; }
        public bool GuestProxyAgentLogGenerated { get; set; }
        public string GuestProxyAgentServiceStatus { get; set; } = null!;
    }
}
