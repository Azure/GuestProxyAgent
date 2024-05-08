// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

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
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot"));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterInstallOrUpdateGuestProxyAgent"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot"));
        }
    }
}
