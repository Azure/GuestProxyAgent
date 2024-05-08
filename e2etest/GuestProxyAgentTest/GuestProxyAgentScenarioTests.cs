// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Utilities;
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestScenarios;

namespace GuestProxyAgentTest
{
    /// <summary>
    /// GuestProxyAgentScenarioTests class for running scenario tests
    /// </summary>
    public class GuestProxyAgentScenarioTests
    {
        /// <summary>
        /// Main function to start each scenario test
        /// </summary>
        /// <param name="testScenarioList"></param>
        /// <returns></returns>
        public async Task StartAsync(List<TestScenarioSetting> testScenarioList)
        {
            var groupTestResultBuilderMap = new Dictionary<string, JunitTestResultBuilder>();
            foreach(var testGroupName in testScenarioList.Select(x => x.testGroupName).ToHashSet())
            {
                groupTestResultBuilderMap[testGroupName] = new JunitTestResultBuilder(TestSetting.Instance.testResultFolder, testGroupName);
            }

            var taskList = new List<Task>();
            var testScenarioStatusList = new List<TestScenarioStatusDetails>();

            foreach (var testScenario in testScenarioList)
            {
                var testScenarioStatusDetails = new TestScenarioStatusDetails()
                {
                    ScenarioName = testScenario.testScenarioName,
                    GroupName = testScenario.testGroupName,
                    Status = ScenarioTestStatus.NotStarted,
                    ErrorMessage = "",
                    Result = ScenarioTestResult.Succeed,
                };
                Task testScenarioTask = null!;

                try
                {
                    if (Activator.CreateInstance(Type.GetType(testScenario.testScenarioClassName)!) is TestScenarioBase @scenario)
                    {
                        testScenarioTask = @scenario
                             .TestScenarioSetting(testScenario)
                             .JUnitTestResultBuilder(groupTestResultBuilderMap[testScenario.testGroupName])
                             .StartAsync(testScenarioStatusDetails);
                        taskList.Add(testScenarioTask);
                    }
                    else
                    {
                        testScenarioStatusDetails.Result = ScenarioTestResult.Failed;
                        testScenarioStatusDetails.Status = ScenarioTestStatus.Completed;
                        testScenarioStatusDetails.ErrorMessage = "Failed to create the scenario class instance: " + testScenario.testScenarioClassName;
                    }

                }
                catch (Exception ex)
                {
                    testScenarioStatusDetails.Result = ScenarioTestResult.Failed;
                    testScenarioStatusDetails.Status = ScenarioTestStatus.Completed;
                    testScenarioStatusDetails.ErrorMessage = ex.Message;
                }
                finally
                {
                    testScenarioStatusList.Add(testScenarioStatusDetails);
                    if (testScenarioTask != null)
                    {
                        taskList.Add(testScenarioTask);
                    }
                }
            }
            var stopMontor = new ManualResetEvent(false);
            var monitoringTask = Task.Run(() =>
            {
                while (!stopMontor.WaitOne(5000))
                {
                    ConsolePrintTestScenariosStatusSummary(testScenarioStatusList);
                }
            });

            try
            {
                await Task.WhenAll(taskList).TimeoutAfter(TestSetting.Instance.testTimeoutMilliseconds);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test execution exception: {ex.Message}");
            }
            
            stopMontor.Set();

            foreach (var groupName in groupTestResultBuilderMap.Keys)
            {
                Console.WriteLine("building test result report for test group: " + groupName);
                groupTestResultBuilderMap[groupName].Build();
            }

            ConsolePrintTestScenariosStatusSummary(testScenarioStatusList);
            ConsolePrintTestScenariosDetailsSummary(testScenarioStatusList);
        }

        private void ConsolePrintTestScenariosStatusSummary(IEnumerable<TestScenarioStatusDetails> testScenarioStatusDetailsList)
        {
            var message = $"Test Running Summary: total {testScenarioStatusDetailsList.Count()}" +
                $", not started {testScenarioStatusDetailsList.Where(x => x.Status == ScenarioTestStatus.NotStarted).Count()}" +
                $", running {testScenarioStatusDetailsList.Where(x => x.Status == ScenarioTestStatus.Running).Count()}" +
                $", failed {testScenarioStatusDetailsList.Where(x => x.Status == ScenarioTestStatus.Completed && x.Result == ScenarioTestResult.Failed).Count()}" +
                $", success {testScenarioStatusDetailsList.Where(x => x.Status == ScenarioTestStatus.Completed && x.Result == ScenarioTestResult.Succeed).Count()}. ";
            Console.WriteLine(message);
        }

        private void ConsolePrintTestScenariosDetailsSummary(IEnumerable<TestScenarioStatusDetails> testScenariosStatusDetailsList)
        {
            var failedScenarios = testScenariosStatusDetailsList.Where(x => x.Status == ScenarioTestStatus.Completed && x.Result == ScenarioTestResult.Failed).ToList();
            var message = $"Total Failed Scenarios: {failedScenarios.Count()}" + Environment.NewLine;
            int i = 1;
            foreach (var fc in failedScenarios)
            {
                message += $"Failed Scenario {i}/{failedScenarios.Count()}: " + Environment.NewLine
                    + $"GroupName: {fc.GroupName}, ScenarioName: {fc.ScenarioName}" + Environment.NewLine
                    + $"Scenario Level ErrorMessage: {fc.ErrorMessage}" + Environment.NewLine
                    + $"Failed Test Cases Summary: {fc.TestCasesErrorMessage}" + Environment.NewLine;
                i++;
            }
            Console.WriteLine(message);
        }
    }
}
