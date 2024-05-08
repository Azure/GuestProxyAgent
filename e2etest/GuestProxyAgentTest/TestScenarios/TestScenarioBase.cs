// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.ResourceManager.Compute;
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.Utilities;
using System.Net;
using GuestProxyAgentTest.Extensions;
using System.Diagnostics;

namespace GuestProxyAgentTest.TestScenarios
{
    /// <summary>
    /// Class for trigger each Test Scenario
    /// </summary>
    public abstract class TestScenarioBase
    {
        private TestScenarioSetting _testScenarioSetting = null!;
        private JunitTestResultBuilder _junitTestResultBuilder = null!;
        private List<TestCaseBase> _testCases = new List<TestCaseBase>();
        protected bool EnableProxyAgent { get; set; }


        public TestScenarioBase()
        {
            TestScenarioSetup();
        }

        public TestScenarioBase TestScenarioSetting(TestScenarioSetting testScenarioSetting)
        {
            this._testScenarioSetting = testScenarioSetting;
            return this;
        }

        public TestScenarioBase JUnitTestResultBuilder(JunitTestResultBuilder junitTestResultBuilder)
        {
            this._junitTestResultBuilder = junitTestResultBuilder;
            return this;
        }

        /// <summary>
        /// Abstract method for sub class(TestScenario) to set up its scenario, including add test case or others settings
        /// </summary>
        public abstract void TestScenarioSetup();

        /// <summary>
        /// Add test case for the scenario
        /// </summary>
        /// <param name="testCase"></param>
        protected void AddTestCase(TestCaseBase testCase)
        {
            this._testCases.Add(testCase);
        }

        private string LogPrefix
        {
            get
            {
                return "Test Group: " + _testScenarioSetting.testGroupName + ", Test Scenario: " + _testScenarioSetting.testScenarioName + ": ";
            }
        }

        protected void ConsoleLog(string msg)
        {
            Console.WriteLine(LogPrefix + msg);
        }

        protected void PreCheck()
        {
            if (_testCases.Count == 0)
            {
                throw new Exception("Test cases list is empty.");
            }

            if (_testScenarioSetting == null)
            {
                throw new Exception("Test scenario setting is not set.");
            }

            if(_junitTestResultBuilder == null)
            {
                throw new Exception("JUnit test result builder is not set");
            }
        }

        /// <summary>
        /// The template workflow for start a test scenario:
        /// 1. build VM
        /// 2. run the test cases one by one
        /// 3. collect GALogs zip
        /// 4. write the test result to Junit format.
        /// 5. save Logs incluing each test case run and collect GALogs zip
        /// 
        /// </summary>
        /// <param name="testScenarioStatusDetails"></param>
        /// <returns></returns>
        public async Task StartAsync(TestScenarioStatusDetails testScenarioStatusDetails)
        {
            try
            {
                await DoStartAsync(testScenarioStatusDetails).TimeoutAfter(_testScenarioSetting.testScenarioTimeoutMillseconds);
            }
            catch (Exception ex)
            {
                ConsoleLog($"Test Scenario {_testScenarioSetting.testScenarioName} Exception: {ex.Message}.");
            }
            finally
            {
                try
                {
                    ConsoleLog("Cleanup generated Azure Resources.");
                    VMHelper.Instance.CleanupTestResources(_testScenarioSetting);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Cleanup azure resources exception: " + ex.Message);
                }
            }
        }


        private async Task DoStartAsync(TestScenarioStatusDetails testScenarioStatusDetails)
        {
            RunCommandOutputDetails collectGALogOutput = null!;
            Stopwatch sw = new Stopwatch();
            try
            {
                ConsoleLog("Running test.");
                sw.Start();
                testScenarioStatusDetails.Status = ScenarioTestStatus.Running;
                PreCheck();

                var vmr = await new VMBuilder().LoadTestCaseSetting(_testScenarioSetting).Build(EnableProxyAgent);
                ConsoleLog("VM created");

                ConsoleLog("Running scenario test: " + _testScenarioSetting.testScenarioName);
                await ScenarioTestAsync(vmr, testScenarioStatusDetails);

                collectGALogOutput = await CollectGALogsOnVMAsync(vmr);
                ConsoleLog("GA log zip collected.");
            }
            catch (Exception ex)
            {
                testScenarioStatusDetails.ErrorMessage = ex.Message;
                testScenarioStatusDetails.Result = ScenarioTestResult.Failed;
                sw.Stop();
                // exception happened at here is outside of test cases under scenario test
                // write to the faiulre to JUNIT with a fixed test case named 'ScenarioTestWorkflow'
                _junitTestResultBuilder.AddFailureTestResult(testScenarioStatusDetails.ScenarioName, "ScenarioTestWorkflow", "", ex.Message + ex.StackTrace?? "", "", sw.ElapsedMilliseconds);
                ConsoleLog("Exception occurs: " + ex.Message);
            }
            finally
            {
                try
                {
                    ConsoleLog("Saving logs.");
                    if (collectGALogOutput != null)
                    {
                        SaveResultFile(collectGALogOutput.StdOut, "collectLogZip", "stdOut.txt");
                        SaveResultFile(collectGALogOutput.StdErr, "collectLogZip", "stdErr.txt");
                        SaveResultFile(collectGALogOutput.CustomOut, "collectLogZip", "GALogs.zip");
                    }

                }
                catch (Exception ex)
                {

                    Console.WriteLine("Saving logs error: " + ex.Message);
                }
            }
            testScenarioStatusDetails.Status = ScenarioTestStatus.Completed;
            ConsoleLog("Test case run finished.");
        }

        private async Task ScenarioTestAsync(VirtualMachineResource vmr, TestScenarioStatusDetails testScenarioStatusDetails)
        {
            testScenarioStatusDetails.Result = ScenarioTestResult.Succeed;
            // always running all the cases inside scenario
            foreach (var testCase in _testCases)
            {
                TestCaseExecutionContext context = new TestCaseExecutionContext(vmr, _testScenarioSetting);
                Stopwatch sw = Stopwatch.StartNew();
                
                try
                {
                    await testCase.StartAsync(context);
                    sw.Stop();
                    context.TestResultDetails
                        .DownloadConentIfFromBlob()
                        .WriteJUnitTestResult(_junitTestResultBuilder, _testScenarioSetting.testScenarioName, testCase.TestCaseName, sw.ElapsedMilliseconds);

                    if (!context.TestResultDetails.Succeed)
                    {
                        testScenarioStatusDetails.FailedCases.Add(testCase.TestCaseName);
                        testScenarioStatusDetails.Result = ScenarioTestResult.Failed;
                    }
                }
                catch (Exception ex)
                {
                    var errorMessage = $"test case: {testCase.TestCaseName} failed with exception: message: {ex.Message}, stack trace: {ex.StackTrace}";
                    testScenarioStatusDetails.FailedCases.Add(testCase.TestCaseName);
                    testScenarioStatusDetails.Result = ScenarioTestResult.Failed;
                    context.TestResultDetails.Succeed = false;
                    context.TestResultDetails.StdErr = errorMessage;
                    context.TestResultDetails.FromBlob = false;
                    sw.Stop();
                    ConsoleLog($"Scenario case {testCase.TestCaseName} exception: {ex.Message}, stack trace: {ex.StackTrace}");
                    _junitTestResultBuilder.AddFailureTestResult(_testScenarioSetting.testScenarioName, testCase.TestCaseName, "", errorMessage, "", sw.ElapsedMilliseconds);
                }
                finally
                {
                    ConsoleLog($"Scenario case {testCase.TestCaseName} finished with result: {(context.TestResultDetails.Succeed? "Succeed": "Falied")} and duration: " + sw.ElapsedMilliseconds + "ms");
                    SaveResultFile(context.TestResultDetails.CustomOut, $"TestCases/{testCase.TestCaseName}", "customOut.txt", context.TestResultDetails.FromBlob);
                    SaveResultFile(context.TestResultDetails.StdErr, $"TestCases/{testCase.TestCaseName}", "stdErr.txt", context.TestResultDetails.FromBlob);
                    SaveResultFile(context.TestResultDetails.StdOut, $"TestCases/{testCase.TestCaseName}", "stdOut.txt", context.TestResultDetails.FromBlob);
                }
            }
        }

        private async Task<RunCommandOutputDetails> CollectGALogsOnVMAsync(VirtualMachineResource vmr)
        {
            var logZipPath = Path.Combine(Path.GetTempPath(), _testScenarioSetting.testGroupName + "_" + _testScenarioSetting.testScenarioName + "_VMAgentLogs.zip");
            using (File.CreateText(logZipPath)) ConsoleLog("Created empty VMAgentLogs.zip file.");
            var logZipSas = StorageHelper.Instance.Upload2SharedBlob(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, logZipPath, _testScenarioSetting.TestScenarioStroageFolderPrefix); ;
            
            var runCommandRes = await RunCommandRunner.ExecuteRunCommandOnVM(vmr, new RunCommandSettingBuilder()
                    .TestScenarioSetting(_testScenarioSetting)
                    .RunCommandName("CollectInVMGALog")
                    .ScriptFullPath(Path.Combine(TestSetting.Instance.scriptsFolder, Constants.COLLECT_INVM_GA_LOG_SCRIPT_NAME))
                    , (builder) =>
                    {
                        return builder.AddParameter("logZipSas", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(logZipSas)));
                    });
            runCommandRes.CustomOut = logZipSas;
            return runCommandRes;
        }

        private void SaveResultFile(string fileContentOrSas, string parentFolderName, string fileName, bool isFromSas = true)
        {
            var fileFolder = Path.Combine(TestSetting.Instance.testResultFolder, _testScenarioSetting.testGroupName, _testScenarioSetting.testScenarioName, parentFolderName);
            Directory.CreateDirectory(fileFolder);
            var filePath = Path.Combine(fileFolder, fileName);
            
            if (isFromSas)
            {
                TestCommonUtilities.DownloadFile(fileContentOrSas, filePath, ConsoleLog);
            }
            else
            {
                File.WriteAllText(filePath, fileContentOrSas);
            }
        }
    }

    /// <summary>
    /// Test case execution context class
    /// container VirtualMachineResouce and TestScenarioSetting
    /// VirtualMachineResouce is the created the Azure VM resource for the test scenario
    /// </summary>
    public class TestCaseExecutionContext
    {
        private VirtualMachineResource _vmr = null!;
        private TestScenarioSetting _testScenarioSetting = null!;

        /// <summary>
        /// TestResultDetails for a particular test case
        /// </summary>
        public TestCaseResultDetails TestResultDetails { get; set; } = new TestCaseResultDetails();

        public TestScenarioSetting ScenarioSetting
        {
            get
            {
                return _testScenarioSetting;
            }
        }

        /// <summary>
        /// the Azure Virtual Machine Resource created for running E2E test
        /// </summary>
        public VirtualMachineResource VirtualMachineResource
        {
            get
            {
                return _vmr;
            }
        }

        public TestCaseExecutionContext(VirtualMachineResource vmr, TestScenarioSetting testScenarioSetting)
        {
            _vmr = vmr;
            _testScenarioSetting = testScenarioSetting;
        }
    }
}
