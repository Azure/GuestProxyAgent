// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;

namespace GuestProxyAgentTest.Utilities
{
    public static class TestCommonUtilities
    {
        /// <summary>
        /// Test Setup, set up all the test related setting
        /// </summary>
        /// <param name="guestProxyAgentZipFilePath"></param>
        /// <param name="testConfigFilePath"></param>
        /// <param name="testResultFolder"></param>
        public static void TestSetup(string guestProxyAgentZipFilePath, string testConfigFilePath, string testResultFolder)
        {
            TestSetting.Init(YamlUtils.DeserializeYaml<TestConfig>(testConfigFilePath), guestProxyAgentZipFilePath, testResultFolder);
            StorageHelper.Init(TestSetting.Instance.tenantId, TestSetting.Instance.appClientId, TestSetting.Instance.cert);
            VMHelper.Init(TestSetting.Instance.tenantId, TestSetting.Instance.appClientId, TestSetting.Instance.subscriptionId, TestSetting.Instance.cert);

        }

        /// <summary>
        /// download the content as string with retry per 1 second
        /// in case of download succeed will retrun (true, content string)
        /// if case of download failed willl return(false, error message)
        /// </summary>
        /// <param name="url">download url</param>
        /// <param name="retryCnt">retry count, default value is 5</param>
        /// <returns></returns>
        public static (bool, string) DownloadContentAsString(string url, Action<string> logger = null!, int retryCnt = 5)
        {
            if (url == null || url.Length == 0)
            {
                return (false, "The url provided is null or empty.");
            }

            int cnt = 0;
            var errMessage = "";
            while (cnt < retryCnt)
            {
                cnt++;
                try
                {
                    string contents = "";
                    using (var client = new HttpClient())
                    {
                        var res = client.GetAsync(url).Result;
                        res.EnsureSuccessStatusCode();
                        contents = res.Content.ReadAsStringAsync().Result;
                    }
                    return (true, contents);
                }
                catch (Exception ex)
                {
                    errMessage = string.Format("Download content failed, attempted: {0} times, exception: {1}", cnt, ex.ToString());
                    logger?.Invoke(errMessage);
                }
                Thread.Sleep(1000);
            }
            return (false, errMessage);
        }

        public static bool DownloadFile(string url, string filePath, Action<string> logger = null!, int retryCnt = 5)
        {
            if (null == url || url.Length == 0)
            {
                return false;
            }
            int cnt = 0;
            while (cnt < retryCnt)
            {
                cnt++;
                try
                {
                    if (File.Exists(filePath))
                    {
                        File.Delete(filePath);
                    }

                    using var client = new HttpClient();
                    var res = client.GetAsync(url).Result;
                    res.EnsureSuccessStatusCode();
                    using var fileStream = File.Create(filePath);
                    res.Content.CopyToAsync(fileStream).Wait();

                    return true;
                }
                catch (Exception ex)
                {
                    var errMessage = string.Format("Download file failed, attempted: {0} times, exception: {1}", cnt, ex.ToString());
                    logger?.Invoke(errMessage);
                }
            }
            return false;

        }
    }
}
