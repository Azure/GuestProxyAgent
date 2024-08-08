// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;
using GuestProxyAgentTest.Settings;
using System.Diagnostics;
using System.IO;
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
            string proxyAgentVersion = "";
            string exePath = "";
            bool imdsSecureChannelEnabled = false;
            try
            {
                ZipFile.ExtractToDirectory(zipFile, extractPath);
                Console.WriteLine("Extraction successful!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
            if (!Constants.IS_WINDOWS())
            {
                AddTestCase(new SetupCGroup2TestCase("SetupCGroup2"));
                AddTestCase(new RebootVMCase("RebootVMCaseAfterSetupCGroup2"));
                AddTestCase(new AddLinuxVMExtensionCase("AddLinuxVMExtensionCase"));
                exePath = extractPath + "/ProxyAgent/ProxyAgent/azure-proxy-agent";
            }
            else
            {
                EnableProxyAgent = true;
                exePath = extractPath + "\\ProxyAgent\\ProxyAgent\\GuestProxyAgent.exe";
                // currently when enable msp, it only enforce WS "secureChannelState: WireServer Enforce -  IMDS Disabled, version: 2.0."
                // TODO: when the preview SDK is available, we need change the code to enforce both WS and IMDS and set the imdsSecureChannelEnabled to true
                imdsSecureChannelEnabled = false;
            }
            var process = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = "--version",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            proxyAgentVersion = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            // Passing in 0 version number for the first validation case
            string proxyAgentVersionBeforeUpdate = "0";
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseBeforeUpdate", proxyAgentVersionBeforeUpdate));
            AddTestCase(new InstallOrUpdateGuestProxyAgentExtensionCase());
            AddTestCase(new GuestProxyAgentExtensionValidationCase("GuestProxyAgentExtensionValidationCaseAfterUpdate", proxyAgentVersion));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestBeforeReboot", imdsSecureChannelEnabled));
            AddTestCase(new RebootVMCase("RebootVMCaseAfterUpdateGuestProxyAgentExtension"));
            AddTestCase(new IMDSPingTestCase("IMDSPingTestAfterReboot", imdsSecureChannelEnabled));
        }
    }
}
