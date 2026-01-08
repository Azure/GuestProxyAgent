// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestScenarios
{
    public class BVTScenario : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            var secureChannelEnabled = false;
            if (!Constants.IS_WINDOWS())
            {
                AddTestCase(new SetupCGroup2TestCase("SetupCGroup2"));
                AddTestCase(new RebootVMCase("RebootVMCaseAfterSetupCGroup2"));
            }
            AddTestCase(new InstallOrUpdateGuestProxyAgentCase());
            AddTestCase(new GuestProxyAgentValidationCase());
            if (Constants.IS_WINDOWS())
            {
                AddTestCase(new GuestProxyAgentLoadedModulesValidationCase());
            }
            else
            {
                // do not enable proxy agent for Windows VM,
                // it will add GPA VM Extension and overwrite the private GPA package
                AddTestCase(new EnableProxyAgentCase());
                secureChannelEnabled = true;
                AddTestCase(new GuestProxyAgentValidationCase("GuestProxyAgentValidationWithSecureChannelEnabled", "WireServer Enforce -  IMDS Audit - HostGA Enforce"));
            }

            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot", secureChannelEnabled));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterInstallOrUpdateGuestProxyAgent"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot", secureChannelEnabled));
        }
    }
}
