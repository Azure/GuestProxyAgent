// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using System.Net;
using System.Xml;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// JUnit test result builder
    /// </summary>
    public class JunitTestResultBuilder
    {
        // key is test suit name, value is junit-doc, junit-suite
        // azure public publish test result task doesn't display result correctly, if result has multiple test suites
        // work around is create one result file per test suite (test scenario in E2E)
        private readonly Dictionary<string, (XmlDocument, XmlElement)> testSuiteMap = new Dictionary<string, (XmlDocument, XmlElement)>();
        private readonly string testGroupName = null!;
        private readonly string testResultGroupFolder = null!;
        internal string testResultFolder = null!;

        public JunitTestResultBuilder(string testResultFolder, string testGroupName)
        {
            this.testGroupName = testGroupName;
            this.testResultGroupFolder = Path.Combine(testResultFolder, testGroupName);
            Directory.CreateDirectory(this.testResultGroupFolder);
            this.testResultFolder = testResultFolder;
        }

        
        /// <summary>
        /// Add success test result, it will merge stdoutput with customoutput.
        /// </summary>
        /// <param name="testScenarioName"></param>
        /// <param name="testName"></param>
        /// <param name="stdOut"></param>
        /// <param name="customOut"></param>
        /// <returns></returns>
        public JunitTestResultBuilder AddSuccessTestResult(string testScenarioName, string testName, string stdOut, string customOut, long durationInMillseconds = 0)
        {
            var stdOutMessage = "Std output:"
                + Environment.NewLine
                + stdOut
                + Environment.NewLine
                + "Custom output:"
                + Environment.NewLine
                + customOut;
            return AddSuccessTestResult(testScenarioName, testName, stdOutMessage, durationInMillseconds);
        }

        /// <summary>
        /// Add succeed test result
        /// </summary>
        /// <param name="testScenarioName"></param>
        /// <param name="testName"></param>
        /// <param name="stdOutMessage"></param>
        /// <returns></returns>
        public JunitTestResultBuilder AddSuccessTestResult(string testScenarioName, string testName, string stdOutMessage, long durationInMillseconds = 0)
        {
            lock (this)
            {
                XmlDocument doc = null!;
                if (!testSuiteMap.ContainsKey(testScenarioName))
                {
                    doc = new XmlDocument();
                    var testsuites = doc.CreateElement("testsuites");
                    doc.AppendChild(testsuites);

                    XmlElement testSuiteElement = doc.CreateElement("testsuite");
                    testSuiteElement.SetAttribute("name", testGroupName + "." + testScenarioName);
                    testSuiteElement.SetAttribute("tests", "0");
                    testSuiteElement.SetAttribute("errors", "0");
                    testSuiteElement.SetAttribute("failures", "0");
                    testSuiteElement.SetAttribute("skipped", "0");
                    testSuiteElement.SetAttribute("timestamp", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"));
                    testsuites.AppendChild(testSuiteElement);
                    testSuiteMap[testScenarioName] = (doc, testSuiteElement);
                }
                doc = testSuiteMap[testScenarioName].Item1;
                var testSuite = testSuiteMap[testScenarioName].Item2;
                testSuite.SetAttribute("tests", StringAdd(testSuite.GetAttribute("tests"), 1));

                XmlElement successTestCaseElement = doc.CreateElement("testcase");
                successTestCaseElement.SetAttribute("name", testName);
                successTestCaseElement.SetAttribute("classname", testGroupName + "." + testScenarioName);
                successTestCaseElement.SetAttribute("time", ((double)durationInMillseconds / 1000).ToString());
                testSuite.AppendChild(successTestCaseElement);

                XmlElement systemOutElement = doc.CreateElement("system-out");
                systemOutElement.InnerText = stdOutMessage;
                successTestCaseElement.AppendChild(systemOutElement);
            }

            return this;
        }

        /// <summary>
        /// Add failure test result
        /// </summary>
        /// <param name="testScenarioName"></param>
        /// <param name="testName"></param>
        /// <param name="stdOutMessage"></param>
        /// <param name="stdErrMessage"></param>
        /// <param name="customOutput"></param>
        /// <returns></returns>
        public JunitTestResultBuilder AddFailureTestResult(string testScenarioName, string testName, string stdOutMessage, string stdErrMessage, string customOutput, long durationInMillseconds = 0)
        {
            lock (this)
            {
                XmlDocument doc = null!;
                if (!testSuiteMap.ContainsKey(testScenarioName))
                {
                    doc = new XmlDocument();
                    var testsuites = doc.CreateElement("testsuites");
                    doc.AppendChild(testsuites);

                    XmlElement testSuiteElement = doc.CreateElement("testsuite");
                    testSuiteElement.SetAttribute("name", testGroupName + "." + testScenarioName);
                    testSuiteElement.SetAttribute("tests", "0");
                    testSuiteElement.SetAttribute("errors", "0");
                    testSuiteElement.SetAttribute("failures", "0");
                    testSuiteElement.SetAttribute("skipped", "0");
                    testSuiteElement.SetAttribute("timestamp", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"));
                    testsuites.AppendChild(testSuiteElement);
                    testSuiteMap[testScenarioName] = (doc, testSuiteElement);
                }
                doc = testSuiteMap[testScenarioName].Item1; 
                var testSuite = testSuiteMap[testScenarioName].Item2;
                testSuite.SetAttribute("tests", StringAdd(testSuite.GetAttribute("tests"), 1));
                testSuite.SetAttribute("failures", StringAdd(testSuite.GetAttribute("failures"), 1));

                XmlElement failedTestCaseElement = doc.CreateElement("testcase");
                failedTestCaseElement.SetAttribute("name", testName);
                failedTestCaseElement.SetAttribute("classname", testGroupName + "." + testScenarioName);
                failedTestCaseElement.SetAttribute("time", ((double)durationInMillseconds/1000).ToString());
                testSuite.AppendChild(failedTestCaseElement);

                XmlElement systemOutElement = doc.CreateElement("system-out");
                systemOutElement.InnerText = stdOutMessage;
                failedTestCaseElement.AppendChild(systemOutElement);

                XmlElement systemErrElement = doc.CreateElement("system-err");
                systemErrElement.InnerText = stdErrMessage;
                failedTestCaseElement.AppendChild(systemErrElement);

                XmlElement failureElement = doc.CreateElement("failure");
                failureElement.SetAttribute("message", "Std Error Ouput: "
                    + Environment.NewLine
                    + stdErrMessage
                    + Environment.NewLine
                    + Environment.NewLine
                    + "Custom output: "
                    + Environment.NewLine
                    + customOutput);
                failureElement.SetAttribute("type", "AssertionException");
                failedTestCaseElement.AppendChild(failureElement);
            }
            return this;
        }

        /// <summary>
        /// build and save the test result to file
        /// </summary>
        /// <returns></returns>
        public List<string> Build()
        {
            List<string> result = new List<string>();
            foreach(KeyValuePair<string, (XmlDocument, XmlElement)> kv in testSuiteMap)
            {
                var doc = kv.Value.Item1;
                var resultPath = Path.Combine(this.testResultGroupFolder, kv.Key + "-TestResults.xml");
                result.Add(resultPath);
                doc.Save(resultPath);
            }
            return result;
        }

        private string StringAdd(string str, int added)
        {
            var val = int.Parse(str) + added;
            return val + "";
        }

    }
}
