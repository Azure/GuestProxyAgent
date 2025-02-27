// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;
using System.Text;

namespace GuestProxyAgentTest.TestCases
{
    public enum TestCaseResult
    {
        NotStarted,
        Running,
        Succeed,
        Failed,
        Aborted,
    }
    
    /// <summary>
    /// Base case for each TestCase
    /// </summary>
    public abstract class TestCaseBase
    {
        /// <summary>
        /// Test Case Name
        /// </summary>
        public string TestCaseName
        {
            get; private set;
        } = null!;

        public TestCaseResult Result { get; set; } = TestCaseResult.NotStarted;

        public TestCaseBase(string testCaseName)
        {
            TestCaseName = testCaseName;
        }

        /// <summary>
        /// Abstract function to start the test case
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public abstract Task StartAsync(TestCaseExecutionContext context);

        /// <summary>
        /// Function to run a script through RunCommandV2 on the VM, that can be used in the inherit class
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scriptFileName"></param>
        /// <param name="parameterList"></param>
        /// <param name="includeCustomJsonOutputSasParam">
        /// if set to true, it will automatically add a parameter named <see cref="Utilities.Constants.RUNCOMMAND_CUSTOM_OUTPUT_SAS_PARAMETER_NAME"/>
        /// the parameter value is base64 encoded blob SAS url, the test script can use it to write customized output info.
        /// if set to false, it will not add the parameter.
        /// </param>
        /// <returns></returns>
        protected async Task<RunCommandOutputDetails> RunScriptViaRunCommandV2Async(TestCaseExecutionContext context, string scriptFileName, List<(string, string)> parameterList, bool includeCustomJsonOutputSasParam = true)
        {
            var testScenarioSetting = context.ScenarioSetting;
            string custJsonSas = null!;
            if (includeCustomJsonOutputSasParam)
            {
                var custJsonPath = Path.Combine(Path.GetTempPath(), $"{testScenarioSetting.testGroupName}_{testScenarioSetting.testScenarioName}_{TestCaseName}.json");
                using (File.CreateText(custJsonPath)) ConsoleLog("Created empty test file for customized json output file.");
                custJsonSas = StorageHelper.Instance.Upload2SharedBlob(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, custJsonPath, "customOutputJson.json", testScenarioSetting.TestScenarioStorageFolderPrefix);
            }
            return await RunCommandRunner.ExecuteRunCommandOnVM(context.VirtualMachineResource, new RunCommandSettingBuilder()
                    .TestScenarioSetting(testScenarioSetting)
                    .RunCommandName(TestCaseName)
                    .ScriptFullPath(Path.Combine(TestSetting.Instance.scriptsFolder, scriptFileName))
                    , (builder) => builder
                        .CustomOutputSas(custJsonSas)
                        .AddParameters(parameterList));
        }

        protected void ConsoleLog(string message) { Console.WriteLine($"[{TestCaseName}]: " + message); }

        protected string FormatVMExtensionData(VirtualMachineExtensionData data)
        {
            if (data == null)
            {
                return "null";
            }
            return string.Format("ProvisioningState: {0}, Publisher: {1}, ExtensionType: {2}, TypeHandlerVersion: {3}, AutoUpgradeMinorVersion: {4}, EnableAutomaticUpgrade: {5}, InstanceView: {6}",
                 data.ProvisioningState, data.Publisher, data.ExtensionType, data.TypeHandlerVersion, data.AutoUpgradeMinorVersion, data.EnableAutomaticUpgrade, FormatVMExtensionInstanceView(data.InstanceView));
        }

        protected string FormatVMExtensionInstanceView(VirtualMachineExtensionInstanceView instanceView)
        {
            if (instanceView == null)
            {
                return "null";
            }
            return string.Format("Name: {0}, ExtensionType:{1}, ExtensionVersion:{2} Statuses: {3}, Substatuses: {4}", instanceView.Name,
                instanceView.VirtualMachineExtensionInstanceViewType, instanceView.TypeHandlerVersion
                , FormatVMInstanceViewStatus(instanceView.Statuses), FormatVMInstanceViewStatus(instanceView.Substatuses));
        }

        protected string FormatVMInstanceViewStatus(IList<InstanceViewStatus> instanceView)
        {
            StringBuilder stringBuilder = new StringBuilder();
            foreach (var status in instanceView)
            {
                stringBuilder.AppendFormat("Code: {0}, Level: {1}, DisplayStatus: {2}, Message: {3}", status.Code, status.Level, status.DisplayStatus, status.Message);
            }
            return stringBuilder.ToString();
        }
    }
}
