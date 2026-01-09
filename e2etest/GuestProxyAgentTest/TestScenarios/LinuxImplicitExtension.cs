// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestScenarios
{
    public class LinuxImplicitExtension : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            if (Constants.IS_WINDOWS())
            {
                throw new InvalidOperationException("LinuxImplicitExtension scenario can only run on Linux VMs.");
            }

            // Passing in 0 version number for the first validation case
            string proxyAgentVersionBeforeUpdate = "0";
            string proxyAgentVersion = Settings.TestSetting.Instance.proxyAgentVersion;
            ConsoleLog(string.Format("Received ProxyAgent Version:{0}", proxyAgentVersion));
            // implicitly enable the Guest Proxy Agent extension by setting EnableProxyAgent to true and AddProxyAgentVMExtension to true
            AddTestCase(new EnableProxyAgentCase("EnableProxyAgentCase", true, true));
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseBeforeUpdate", proxyAgentVersionBeforeUpdate));
            AddTestCase(new InstallOrUpdateGuestProxyAgentExtensionCase());
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseAfterUpdate", proxyAgentVersion));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot", true));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterUpdateGuestProxyAgentExtension"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot", true));
        }
    }
}
