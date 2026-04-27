// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestScenarios
{
    public class BakedInScenario : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            if (Constants.IS_WINDOWS())
            {
                throw new InvalidOperationException("GPA BakedIn scenario can only run on Linux VMs.");
            }

            var secureChannelEnabled = true;
            EnableProxyAgentForNewVM = true;
            AddTestCase(new GuestProxyAgentValidationCase("GuestProxyAgentValidationWithSecureChannelEnabled", "WireServer Enforce -  IMDS Enforce - HostGA Enforce"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot", secureChannelEnabled));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterInstallOrUpdateGuestProxyAgent"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot", secureChannelEnabled));
        }
    }
}
