// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestScenarios
{
    public class ProxyAgentExtension : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            EnableProxyAgent = true;
            AddTestCase(new GuestProxyAgentExtensionValidationCase("BeforeUpdate"));
            AddTestCase(new InstallOrUpdateGuestProxyAgentExtensionCase());
            AddTestCase(new GuestProxyAgentExtensionValidationCase("AfterUpdate"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot"));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterUpdateGuestProxyAgentExtension"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot"));
        }
    }
}
