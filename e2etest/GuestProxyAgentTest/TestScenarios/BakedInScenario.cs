// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;
using System.Threading.Channels;

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

            var secureChannelEnabled = false;
            EnableProxyAgentForNewVM = false;
            AddTestCase(new GuestProxyAgentValidationCase("GuestProxyAgentValidationWithoutMSP", "disabled"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeEnableMSP", secureChannelEnabled));

            // enable secure channel after validation to test IMDS connectivity with secure channel enabled, 
            AddTestCase(new EnableProxyAgentCase());
            secureChannelEnabled = true;
            AddTestCase(new GuestProxyAgentValidationCase("GuestProxyAgentValidationWithSecureChannelEnabled", "WireServer Enforce -  IMDS Enforce - HostGA Enforce"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot", secureChannelEnabled));

            // then reboot to verify the secure channel state is preserved across reboots
            AddTestCase(new RebootVMCase("RebootVMCaseAfterEnableMSP"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot", secureChannelEnabled));
        }
    }
}
