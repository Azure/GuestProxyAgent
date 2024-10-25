// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;

namespace GuestProxyAgentTest.TestScenarios
{
    public class LinuxPackageScenario : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            AddTestCase(new SetupCGroup2TestCase("SetupCGroup2"));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterSetupCGroup2"));
            AddTestCase(new InstallOrUpdateGuestProxyAgentPackageCase());
            AddTestCase(new GuestProxyAgentValidationCase());
            AddTestCase(new EnableProxyAgentCase());
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot", true));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterInstallOrUpdateGuestProxyAgent"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot", true));
        }
    }
}
