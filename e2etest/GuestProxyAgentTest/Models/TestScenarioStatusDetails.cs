// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
namespace GuestProxyAgentTest.Models
{
    /// <summary>
    /// Test case run status details
    /// </summary>
    public class TestScenarioStatusDetails
    {
        /// <summary>
        /// Indicate if the test case is not-started, running, or completed
        /// </summary>
        public ScenarioTestStatus Status { get; set; } = ScenarioTestStatus.NotStarted;
        /// <summary>
        /// test case group name
        /// </summary>
        public string GroupName { get; set; } = null!;
        /// <summary>
        /// test case name
        /// </summary>
        public string ScenarioName { get; set; } = null!;
        /// <summary>
        /// Error Message in Scenario Level Execution
        /// </summary>
        public string ErrorMessage { get; set; } = null!;
        /// <summary>
        /// test case result
        /// </summary>
        public ScenarioTestResult Result { get; set; }

        public List<string> FailedCases { get; } = new List<string>();

        /// <summary>
        /// Failed test cases summary error message
        /// </summary>
        public string TestCasesErrorMessage
        {
            get
            {
                return FailedCases.Count() == 0? "": $"Test Scenario:{ScenarioName} failed by test cases: {string.Join(',', FailedCases)}, Check the test case log for error details.";
            }
        }
    }

    public enum ScenarioTestStatus
    {
        NotStarted,
        Running,
        Completed,
    }

    public enum ScenarioTestResult
    {
        Succeed,
        Failed
    }
}
