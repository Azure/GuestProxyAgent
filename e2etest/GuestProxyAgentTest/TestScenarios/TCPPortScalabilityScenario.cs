// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestScenarios
{
    public class TCPPortScalabilityScenario : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            if (!Constants.IS_WINDOWS())
            {
                throw new InvalidOperationException("TCPPortScalability Scenario can only run on Windows VMs.");
            }

            string proxyAgentVersion = Settings.TestSetting.Instance.proxyAgentVersion;
            ConsoleLog(string.Format("Received ProxyAgent Version:{0}", proxyAgentVersion));

            // This scenario must enable MSP for the new VM to test TCP port scalability.
            EnableProxyAgentForNewVM = true;

            AddTestCase(new InstallOrUpdateGuestProxyAgentExtensionCase());
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseAfterUpdate", proxyAgentVersion));
            AddTestCase(new TCPPortScalabilityCase());
            // reboot the VM to let the TCP port scalability take effect.
            AddTestCase(new RebootVMCase("RebootVMCaseAfterConfigTCPPortScalability"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestForPortScalability", true));
        }
    }
}