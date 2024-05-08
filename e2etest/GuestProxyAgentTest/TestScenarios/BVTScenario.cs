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
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot"));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterInstallOrUpdateGuestProxyAgent"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot"));
        }
    }
}
