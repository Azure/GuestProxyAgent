// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestCases
{
    /// <summary>
    /// Install or Update Guest Proxy Agent through Msi test case
    /// </summary>
    public class InstallOrUpdateGuestProxyAgentCase : TestCaseBase
    {
        public InstallOrUpdateGuestProxyAgentCase() : base("InstallOrUpdateGuestProxyAgentCase")
        {
        }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            var runCommandRes = await RunCommandRunner.ExecuteRunCommandOnVM(context.VirtualMachineResource, new RunCommandSettingBuilder()
                    .TestScenarioSetting(context.ScenarioSetting)
                    .RunCommandName("InstallOrUpdateProxyAgentMsi")
                    .ScriptFullPath(Path.Combine(TestSetting.Instance.scriptsFolder, Constants.INSTALL_GUEST_PROXY_AGENT_SCRIPT_NAME))
                    , (builder) =>
                    {
                        var zipsas = StorageHelper.Instance.Upload2SharedBlob(Constants.SHARED_MSI_CONTAINER_NAME, TestSetting.Instance.zipFilePath, context.ScenarioSetting.TestScenarioStroageFolderPrefix);
                        return builder.AddParameter("zipsas", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(zipsas)));
                    });
            context.TestResultDetails = new Models.TestCaseResultDetails
            {
                Succeed = runCommandRes.Succeed,
                StdErr = runCommandRes.StdErr,
                StdOut = runCommandRes.StdOut,
                FromBlob = true
            };
        }
    }
}
