// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Utilities;
using GuestProxyAgentTest.Models;
using System.Net;
using Newtonsoft.Json;

namespace GuestProxyAgentTest.Extensions
{
    /// <summary>
    /// Extension methods for data model, that translate one model to another.
    /// </summary>
    public static class ModelExtensions
    {
        public static TestCaseResultDetails ToTestResultDetails(this RunCommandOutputDetails runCommandOutputDetails, Action<string> logger = null!, bool downloadContentFromBlob = true)
        {
            return new TestCaseResultDetails
            {
                StdOut = runCommandOutputDetails.StdOut,
                StdErr = runCommandOutputDetails.StdErr,
                Succeed = runCommandOutputDetails.Succeed,
                CustomOut = runCommandOutputDetails.CustomOut,
                FromBlob = downloadContentFromBlob
            }.DownloadConentIfFromBlob(logger);
        }

        public static TestCaseResultDetails DownloadConentIfFromBlob(this TestCaseResultDetails testCaseResultDetails, Action<string> logger = null!)
        {
            if(!testCaseResultDetails.FromBlob)
            {
                return testCaseResultDetails;
            }
            
            testCaseResultDetails.FromBlob = false;
            var downloadSucceed = true;
            
            if (!string.IsNullOrEmpty(testCaseResultDetails.StdOut))
            {
                var stdOutDownload = TestCommonUtilities.DownloadContentAsString(testCaseResultDetails.StdOut, logger);
                testCaseResultDetails.StdOut = stdOutDownload.Item2;
                if(!stdOutDownload.Item1)
                {
                    downloadSucceed = false;
                }
            }

            if (!string.IsNullOrEmpty(testCaseResultDetails.StdErr))
            {
                var stdErrDownload = TestCommonUtilities.DownloadContentAsString(testCaseResultDetails.StdErr, logger);
                testCaseResultDetails.StdErr = stdErrDownload.Item2;
                if(!stdErrDownload.Item1)
                {
                    downloadSucceed = false;
                }
            }

            if (!string.IsNullOrEmpty(testCaseResultDetails.CustomOut))
            {
                var custOutDownload = TestCommonUtilities.DownloadContentAsString(testCaseResultDetails.CustomOut, logger);
                testCaseResultDetails.CustomOut = custOutDownload.Item2;
                if(!custOutDownload.Item1)
                {
                    downloadSucceed = false;
                }
            }

            if (!downloadSucceed)
            {
                // in case of any download failed, mark the test result as failed and set the std error as combined string from all the download result
                testCaseResultDetails.Succeed = false;
                testCaseResultDetails.StdErr = string.Format("Download content from blob failed: \n stdOut: {0}\n stdError: {1}\n customOut: {2}"
                    , testCaseResultDetails.StdOut
                    , testCaseResultDetails.StdErr
                    , testCaseResultDetails.CustomOut);
            } 

            return testCaseResultDetails;
        }

        public static void WriteJUnitTestResult(this TestCaseResultDetails testCaseResultDetails, JunitTestResultBuilder testResultBuilder, string testScenarioName, string testCaseName, long durationInMillseconds = 0)
        {
            if(testCaseResultDetails.Succeed)
            {
                testResultBuilder.AddSuccessTestResult(testScenarioName, testCaseName, testCaseResultDetails.StdOut, testCaseResultDetails.CustomOut, durationInMillseconds);
            }
            else
            {
                testResultBuilder.AddFailureTestResult(testScenarioName, testCaseName, testCaseResultDetails.StdOut, testCaseResultDetails.StdErr, testCaseResultDetails.CustomOut, durationInMillseconds);
            }
        }

        /// <summary>
        /// Safely do json deserialize customout as the object
        /// In case of error, return null
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="testCaseResultDetails"></param>
        /// <returns></returns>
        public static T SafeDeserializedCustomOutAs<T>(this TestCaseResultDetails testCaseResultDetails) where T: class
        {
            try
            {
                return JsonConvert.DeserializeObject<T>(testCaseResultDetails.CustomOut);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Deserialzied custom out json string failed with exception: " + ex.ToString());
            }
            return null;
        }
    }
}
