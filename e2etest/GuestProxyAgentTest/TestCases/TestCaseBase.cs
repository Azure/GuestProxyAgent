// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.TestCases
{
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
        /// <param name="inCludeCustomJsonOutputSasParam">
        /// if set to true, it will automcatically add a paramter named <see cref="Utilities.Constants.RUNCOMMAND_CUSTOM_OUTPUT_SAS_PARAMETER_NAME"/>
        /// the parameter value is base64 econded blob SAS url, the test script can use it to write cutomized output info.
        /// if set to false, it will not add the parameter.
        /// </param>
        /// <returns></returns>
        protected async Task<RunCommandOutputDetails> RunScriptViaRunCommandV2Async(TestCaseExecutionContext context, string scriptFileName, List<(string, string)> parameterList, bool inCludeCustomJsonOutputSasParam = true)
        {
            var testScenarioSetting = context.ScenarioSetting;
            string custJsonSas = null!;
            if(inCludeCustomJsonOutputSasParam)
            {
                var custJsonPath = Path.Combine(Path.GetTempPath(), $"{testScenarioSetting.testGroupName}_{testScenarioSetting.testScenarioName}_{TestCaseName}.json");
                using (File.CreateText(custJsonPath)) ConsoleLog("Created empty test file for customized json output file.");
                custJsonSas = StorageHelper.Instance.Upload2SharedBlob(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, custJsonPath, "customOutputJson.json", testScenarioSetting.TestScenarioStroageFolderPrefix);
            }
            return await RunCommandRunner.ExecuteRunCommandOnVM(context.VirtualMachineResource, new RunCommandSettingBuilder()
                    .TestScenarioSetting(testScenarioSetting)
                    .RunCommandName(TestCaseName)
                    .ScriptFullPath(Path.Combine(TestSetting.Instance.scriptsFolder, scriptFileName))
                    , (builder) => builder
                        .CustomOutputSas(custJsonSas)
                        .AddParameters(parameterList));
        }

        protected void ConsoleLog(string message) { Console.WriteLine($"[{TestCaseName}]: " + message);}
    }
}
