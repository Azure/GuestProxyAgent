// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// create validation test to check the guest proxy agent service status and log file 
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestCases
{
    public class GuestProxyAgentExtensionValidationCase : TestCaseBase
    {
        public GuestProxyAgentExtensionValidationCase() : base("GuestProxyAgentExtensionValidationCase")
        { }
        public GuestProxyAgentExtensionValidationCase(string testCaseName) : base(testCaseName)
        { }
        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, Constants.GUEST_PROXY_AGENT_EXTENSION_VALIDATION_SCRIPT_NAME, null!)).ToTestResultDetails(ConsoleLog);
            if (context.TestResultDetails.Succeed && context.TestResultDetails.CustomOut != null)
            {
                var validationDetails = context.TestResultDetails.SafeDeserializedCustomOutAs<GuestProxyAgentExtensionValidationDetails>();
                if (validationDetails != null
                    && validationDetails.guestProxyAgentExtensionServiceExist
                    && validationDetails.guestProxyAgentExtensionProcessExist
                    && validationDetails.guestProxyAgentExtensionServiceStatus
                    && validationDetails.guestProxyAgentExtensionStatusObjGenerated
                    && validationDetails.guestProxyAgentExtensionVersion
                    && validationDetails.guestProxyAgentExtensionKeyLatch)
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

    class GuestProxyAgentExtensionValidationDetails
    {
        public bool guestProxyAgentExtensionServiceExist { get; set; }
        public bool guestProxyAgentExtensionProcessExist { get; set; }
        public bool guestProxyAgentExtensionServiceStatus { get; set; }
        public bool guestProxyAgentExtensionStatusObjGenerated { get; set; }
        public bool guestProxyAgentExtensionVersion { get; set; }
        public bool guestProxyAgentExtensionKeyLatch { get; set; }
    }
}