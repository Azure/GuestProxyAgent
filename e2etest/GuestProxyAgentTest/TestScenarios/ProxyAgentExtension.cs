// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;
using System.Diagnostics;
using System.IO.Compression;

namespace GuestProxyAgentTest.TestScenarios
{
    public class ProxyAgentExtension : TestScenarioBase
    {
        public override void TestScenarioSetup()
        {
            string zipFile = Settings.TestSetting.Instance.zipFilePath;
            string withoutExt = Path.GetFileNameWithoutExtension(zipFile);
            string extractPath = Path.Combine(Path.GetDirectoryName(zipFile), withoutExt);
            // Passing in 0 version number for the first validation case
            string proxyAgentVersionBeforeUpdate = "0";
            string proxyAgentVersion = Settings.TestSetting.Instance.proxyAgentVersion;
            ConsoleLog(string.Format("Received ProxyAgent Version:{0}", proxyAgentVersion));

            if (!Constants.IS_WINDOWS())
            {
                AddTestCase(new SetupCGroup2TestCase("SetupCGroup2"));
                AddTestCase(new RebootVMCase("RebootVMCaseAfterSetupCGroup2"));
                AddTestCase(new AddLinuxVMExtensionCase("AddLinuxVMExtensionCase"));
                AddTestCase(new EnableProxyAgentCase());
            }
            else
            {
                EnableProxyAgentForNewVM = true;
            }

            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseBeforeUpdate", proxyAgentVersionBeforeUpdate));
            AddTestCase(new InstallOrUpdateGuestProxyAgentExtensionCase());
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseAfterUpdate", proxyAgentVersion));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot", true));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterUpdateGuestProxyAgentExtension"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot", true));
        }
    }
}
