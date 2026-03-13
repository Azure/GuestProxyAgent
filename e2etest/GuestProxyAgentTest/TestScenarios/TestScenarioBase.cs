// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure;
using Azure.ResourceManager.Compute;
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace GuestProxyAgentTest.TestScenarios
{
    /// <summary>
    /// Class for trigger each Test Scenario
    /// </summary>
    public abstract class TestScenarioBase
    {
        private TestScenarioSetting _testScenarioSetting = null!;
        private VMBuilder _vmBuilder = null!;
        private JunitTestResultBuilder _junitTestResultBuilder = null!;
        private List<TestCaseBase> _testCases = new List<TestCaseBase>();
        protected TestLogger Logger
        {
            get; private set;
        }

        protected bool EnableProxyAgentForNewVM { get; set; }


        public TestScenarioBase()
        {
            Logger = new TestLogger(this.LogPrefix);
            TestScenarioSetup();
        }

        public TestScenarioBase TestScenarioSetting(TestScenarioSetting testScenarioSetting)
        {
            this._testScenarioSetting = testScenarioSetting;
            // refresh the Logger with new LogPrefix which is based on the test scenario setting
            Logger = new TestLogger(this.LogPrefix);
            this._vmBuilder = new VMBuilder().LoadTestCaseSetting(testScenarioSetting);
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
                // _testScenarioSetting may still null in constructor functions
                if (_testScenarioSetting == null)
                {
                    return "Test Scenario: "+this.GetType().Name;
                }
                else
                {
                    return "Test Group: " + _testScenarioSetting?.testGroupName + ", Test Scenario: " + _testScenarioSetting?.testScenarioName;
                }
            }
        }

        protected void ConsoleLog(string msg)
        {
            Logger.Log(msg);
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

            if (_junitTestResultBuilder == null)
            {
                throw new Exception("JUnit test result builder is not set");
            }

            if (_vmBuilder == null)
            {
                throw new Exception("VM builder is not set");
            }
        }

        /// <summary>
        /// The template workflow for start a test scenario:
        /// 1. build VM
        /// 2. run the test cases one by one
        /// 3. collect GALogs zip
        /// 4. write the test result to Junit format.
        /// 5. save Logs including each test case run and collect GALogs zip
        /// 
        /// </summary>
        /// <param name="testScenarioStatusDetails"></param>
        /// <returns></returns>
        public async Task StartAsync(TestScenarioStatusDetails testScenarioStatusDetails)
        {
            PreCheck();
            try
            {
                // Create a cancellation token source that will be used to cancel the running test scenario/cases
                CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
                await DoStartAsync(testScenarioStatusDetails, cancellationTokenSource.Token).TimeoutAfter(_testScenarioSetting.testScenarioTimeoutMilliseconds, cancellationTokenSource);
            }
            catch (Exception ex)
            {
                ConsoleLog($"Test Scenario {_testScenarioSetting.testScenarioName} Exception: {ex.Message}.");

                // set running test cases to failed
                // set not started test cases to aborted
                ex.UpdateTestCaseResults(_testCases, _junitTestResultBuilder, _testScenarioSetting.testScenarioName);
            }
            finally
            {
                try
                {
                    await CollectGALogsOnVMAsync();
                }
                catch (Exception ex)
                {
                    ConsoleLog("Collect GA Logs error: " + ex.Message);
                }

                try
                {
                    ConsoleLog("Cleanup generated Azure Resources.");
                    VMHelper.Instance.CleanupTestResources(_testScenarioSetting);
                }
                catch (Exception ex)
                {
                    ConsoleLog("Cleanup azure resources exception: " + ex.Message);
                }
            }
        }

        /// <summary>
        /// Try to parse alternative VM sizes from the AllocationFailed error message.
        /// Expected pattern: "Alternative VM sizes for the same region: Standard_D2as_v5, Standard_D4as_v5."
        /// </summary>
        private static List<string> ParseAlternativeVmSizes(string errorMessage)
        {
            var alternativeSizes = new List<string>();
            var match = Regex.Match(errorMessage, @"Alternative VM sizes for the same region:\s*(.+?)\.?\s*$", RegexOptions.Multiline);
            if (match.Success)
            {
                var sizes = match.Groups[1].Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                alternativeSizes.AddRange(sizes.Where(s => !string.IsNullOrWhiteSpace(s)));
            }
            return alternativeSizes;
        }

        private async Task DoStartAsync(TestScenarioStatusDetails testScenarioStatusDetails, CancellationToken cancellationToken)
        {
            try
            {
                ConsoleLog("Running test.");
                testScenarioStatusDetails.Status = ScenarioTestStatus.Running;

                VirtualMachineResource vmr;
                Stopwatch sw = Stopwatch.StartNew();
                var vmCreateTestName = "CreateVM";
                try
                {
                    ConsoleLog(string.Format("Creating {0} VM...", _testScenarioSetting.VMImageDetails.IsArm64 ? "ARM64" : "AMD64"));
                    vmr = await _vmBuilder.Build(this.Logger, this.EnableProxyAgentForNewVM, cancellationToken);
                    ConsoleLog("VM Create succeed");
                    sw.Stop();
                    _junitTestResultBuilder.AddSuccessTestResult(_testScenarioSetting.testScenarioName, vmCreateTestName, "VM Create succeed", "", sw.ElapsedMilliseconds);
                }
                catch (Exception ex)
                {
                    ConsoleLog($"VM first create failed with exception: {ex.GetType().Name} - {ex.Message}");

                    // catch ErrorCode: AllocationFailed and retry with different VMSize if possible,
                    // as sometimes the allocation failure is caused by the specific VM size is not available in the region,
                    // but other VM sizes are still available.
                    if (ex is RequestFailedException rfEx && rfEx.ErrorCode == "AllocationFailed")
                    {
                        var alternativeSizes = ParseAlternativeVmSizes(rfEx.Message);
                        bool retrySucceeded = false;
                        if (alternativeSizes.Count > 0)
                        {
                            ConsoleLog($"AllocationFailed for VM size '{TestSetting.Instance.vmSize}'. Retrying with alternative VM sizes: {string.Join(", ", alternativeSizes)}");
                            foreach (var altSize in alternativeSizes)
                            {
                                try
                                {
                                    ConsoleLog($"Retrying VM creation with VM size: {altSize}");
                                    vmr = await _vmBuilder.Build(this.Logger, this.EnableProxyAgentForNewVM, altSize, false, cancellationToken);
                                    ConsoleLog($"VM Create succeed with alternative VM size: {altSize}");
                                    retrySucceeded = true;
                                    break;
                                }
                                catch (RequestFailedException retryRfEx) when (retryRfEx.ErrorCode == "AllocationFailed")
                                {
                                    ConsoleLog($"AllocationFailed for alternative VM size '{altSize}', trying next alternative if available.");
                                    continue;
                                }
                                catch (Exception retryEx)
                                {
                                    // NOT AllocationFailed exception, assume retry succeeded but with other exception, break the loop to avoid retrying other sizes
                                    retrySucceeded = true;
                                    ConsoleLog($"VM creation failed with alternative VM size '{altSize}' with exception: {retryEx.Message}. Not retrying other sizes.");
                                    break;
                                }
                            }
                        }
                        else
                        {
                            var availableVMSize = await _vmBuilder.GetAvailableVmSizeAsync(this.Logger);
                            ConsoleLog($"AllocationFailed but no alternative VM sizes found in the error message, last retry with available VM size `{availableVMSize}`.");
                            vmr = await _vmBuilder.Build(this.Logger, this.EnableProxyAgentForNewVM, availableVMSize, false, cancellationToken);
                            ConsoleLog($"VM Create succeed with available VM size {availableVMSize}.");
                            retrySucceeded = true;
                        }

                        if (!retrySucceeded)
                        {
                            // All alternative sizes also failed, rethrow the original exception
                            sw.Stop();
                            _junitTestResultBuilder.AddFailureTestResult(testScenarioStatusDetails.ScenarioName, vmCreateTestName, "", ex.Message + ex.StackTrace ?? "", "", sw.ElapsedMilliseconds);
                            throw;
                        }
                    }

                    // if the VM Creation operation failed, try check the VM instance view for 5 minutes
                    var startTime = DateTime.UtcNow;
                    while (true)
                    {
                        vmr = await _vmBuilder.GetVirtualMachineResource();
                        var instanceView = await vmr.InstanceViewAsync(cancellationToken: cancellationToken);
                        if (instanceView?.Value?.Statuses?.Count > 0 && (instanceView.Value.Statuses[0].DisplayStatus == "Provisioning succeeded"
                            || instanceView.Value.Statuses[0].DisplayStatus == "VM running"))
                        {
                            ConsoleLog("VM Create succeed");
                            sw.Stop();
                            _junitTestResultBuilder.AddSuccessTestResult(_testScenarioSetting.testScenarioName, vmCreateTestName, "VM Create succeed", "", sw.ElapsedMilliseconds);
                            break;
                        }

                        if (DateTime.UtcNow - startTime > TimeSpan.FromMinutes(5))
                        {
                            // poll timed out, rethrow the exception
                            sw.Stop();
                            _junitTestResultBuilder.AddFailureTestResult(testScenarioStatusDetails.ScenarioName, vmCreateTestName, "", ex.Message + ex.StackTrace ?? "", "", sw.ElapsedMilliseconds);
                            throw;
                        }

                        // wait for 10 seconds before polling again
                        await Task.Delay(10000);
                    }
                }

                ConsoleLog("Running scenario test: " + _testScenarioSetting.testScenarioName);
                await ScenarioTestAsync(vmr, testScenarioStatusDetails, cancellationToken);
            }
            catch (Exception ex)
            {
                ConsoleLog("ExceptionType: " + ex.GetType().FullName);
                testScenarioStatusDetails.ErrorMessage = ex.Message;
                testScenarioStatusDetails.Result = ScenarioTestResult.Failed;
                ConsoleLog("Exception occurs: " + ex.Message);
            }

            testScenarioStatusDetails.Status = ScenarioTestStatus.Completed;
            ConsoleLog("Test scenario run finished.");
        }

        private async Task ScenarioTestAsync(VirtualMachineResource vmr, TestScenarioStatusDetails testScenarioStatusDetails, CancellationToken cancellationToken)
        {
            testScenarioStatusDetails.Result = ScenarioTestResult.Succeed;
            // always running all the cases inside scenario
            foreach (var testCase in _testCases)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (cancellationToken.IsCancellationRequested)
                {
                    ConsoleLog($"Test case {testCase.TestCaseName} is cancelled.");
                    break;
                }

                TestCaseExecutionContext context = new TestCaseExecutionContext(this.Logger, vmr, _testScenarioSetting, cancellationToken);
                Stopwatch sw = Stopwatch.StartNew();

                try
                {
                    ConsoleLog($"Starting test case: {testCase.TestCaseName}");
                    testCase.Result = TestCaseResult.Running;
                    await testCase.StartAsync(context);
                    sw.Stop();
                    context.TestResultDetails
                        .DownloadContentIfFromBlob()
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
                    testCase.Result = context.TestResultDetails.Succeed ? TestCaseResult.Succeed : TestCaseResult.Failed;
                    ConsoleLog($"Test case {testCase.TestCaseName} finished with result: {(context.TestResultDetails.Succeed ? "Succeed" : "Failed")} and duration: " + sw.ElapsedMilliseconds + "ms");
                    SaveResultFile(context.TestResultDetails.CustomOut, $"TestCases/{testCase.TestCaseName}", "customOut.txt", context.TestResultDetails.FromBlob);
                    SaveResultFile(context.TestResultDetails.StdErr, $"TestCases/{testCase.TestCaseName}", "stdErr.txt", context.TestResultDetails.FromBlob);
                    SaveResultFile(context.TestResultDetails.StdOut, $"TestCases/{testCase.TestCaseName}", "stdOut.txt", context.TestResultDetails.FromBlob);
                }
            }
        }

        private async Task CollectGALogsOnVMAsync()
        {
            ConsoleLog("Collecting GA logs on VM.");
            var vmr = await _vmBuilder.GetVirtualMachineResource();
            var logZipPath = Path.Combine(Path.GetTempPath(), _testScenarioSetting.testGroupName + "_" + _testScenarioSetting.testScenarioName + "_VMAgentLogs.zip");
            using (File.CreateText(logZipPath))
            {
                ConsoleLog("Created empty VMAgentLogs.zip file.");
            }
            var logZipSas = StorageHelper.Instance.Upload2SharedBlob(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, logZipPath, _testScenarioSetting.TestScenarioStorageFolderPrefix);

            var collectGALogOutput = await RunCommandRunner.ExecuteRunCommandOnVM(this.Logger, vmr, new RunCommandSettingBuilder()
                    .TestScenarioSetting(_testScenarioSetting)
                    .RunCommandName("CollectInVMGALog")
                    .ScriptFullPath(Path.Combine(TestSetting.Instance.scriptsFolder, Constants.COLLECT_INVM_GA_LOG_SCRIPT_NAME))
                    , CancellationToken.None
                    , (builder) =>
                    {
                        return builder.AddParameter("logZipSas", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(logZipSas)));
                    });
            collectGALogOutput.CustomOut = logZipSas;

            ConsoleLog("GA log zip collected.");

            SaveResultFile(collectGALogOutput.StdOut, "collectLogZip", "stdOut.txt");
            SaveResultFile(collectGALogOutput.StdErr, "collectLogZip", "stdErr.txt");
            SaveResultFile(collectGALogOutput.CustomOut, "collectLogZip", "GALogs.zip");
            ConsoleLog("GA log zip saved.");
        }

        private void SaveResultFile(string fileContentOrSas, string parentFolderName, string fileName, bool isFromSas = true)
        {
            var fileFolder = Path.Combine(TestSetting.Instance.testResultFolder, _testScenarioSetting.testGroupName, _testScenarioSetting.testScenarioName, parentFolderName);
            Directory.CreateDirectory(fileFolder);
            var filePath = Path.Combine(fileFolder, fileName);

            if (isFromSas)
            {
                TestCommonUtilities.DownloadFile(fileContentOrSas, filePath, this.Logger);
            }
            else
            {
                File.WriteAllText(filePath, fileContentOrSas);
            }
        }
    }

    /// <summary>
    /// Test case execution context class
    /// container VirtualMachineResource and TestScenarioSetting
    /// VirtualMachineResource is the created the Azure VM resource for the test scenario
    /// </summary>
    public class TestCaseExecutionContext
    {
        private VirtualMachineResource _vmr = null!;
        private TestScenarioSetting _testScenarioSetting = null!;
        private CancellationToken _cancellationToken;
        private TestLogger _logger = null!;

        /// <summary>
        /// TestResultDetails for a particular test case
        /// </summary>
        public TestCaseResultDetails TestResultDetails { get; set; } = new TestCaseResultDetails();

        public TestLogger Logger
        {
            get
            {
                return _logger;
            }
        }

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

        public CancellationToken CancellationToken
        {
            get
            {
                return _cancellationToken;
            }
        }

        public TestCaseExecutionContext(TestLogger logger, VirtualMachineResource vmr, TestScenarioSetting testScenarioSetting, CancellationToken cancellationToken)
        {
            _logger = logger;
            _vmr = vmr;
            _testScenarioSetting = testScenarioSetting;
            _cancellationToken = cancellationToken;
        }
    }
}
