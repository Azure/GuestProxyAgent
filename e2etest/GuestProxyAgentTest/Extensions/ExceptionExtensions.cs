using GuestProxyAgentTest.TestCases;
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest.Extensions
{
    public static class ExceptionExtensions
    {
        public static void UpdateTestCaseResults(this Exception ex, List<TestCaseBase> testCases, JunitTestResultBuilder junitTestResultBuilder, string testScenarioName)
        {
            foreach (var testCase in testCases)
            {
                if (testCase.Result == TestCaseResult.Running)
                {
                    testCase.Result = TestCaseResult.Failed;
                    junitTestResultBuilder.AddFailureTestResult(testScenarioName, testCase.TestCaseName, "", "Test case timed out.", ex.Message, 0);
                }
                else if (testCase.Result == TestCaseResult.NotStarted)
                {
                    testCase.Result = TestCaseResult.Aborted;
                    junitTestResultBuilder.AddAbortedTestResult(testScenarioName, testCase.TestCaseName, "Test case not started.");
                }
            }
        }
    }
}
