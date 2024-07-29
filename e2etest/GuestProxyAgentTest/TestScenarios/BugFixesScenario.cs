// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;

namespace GuestProxyAgentTest.TestScenarios
{
    public class BugFixesScenario : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            AddTestCase(new InstallOrUpdateGuestProxyAgentCase());
            AddTestCase(new GuestProxyAgentValidationCase());
            AddTestCase(new TCPPortScalabilityCase());
            //AddTestCase(new LocalIPBindingCase());
        }
    }
}