// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using Newtonsoft.Json;
using System.Runtime.Serialization;

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
        public static void TestSetup(string guestProxyAgentZipFilePath, string testConfigFilePath, string testResultFolder, string proxyAgentVersion)
        {
            TestSetting.Init(YamlUtils.DeserializeYaml<TestConfig>(testConfigFilePath), guestProxyAgentZipFilePath, testResultFolder, proxyAgentVersion);
            StorageHelper.Init(TestSetting.Instance.tenantId, TestSetting.Instance.appClientId);
            VMHelper.Init(TestSetting.Instance.tenantId, TestSetting.Instance.appClientId, TestSetting.Instance.subscriptionId);

        }

        /// <summary>
        /// download the content as string with retry per 1 second
        /// in case of download succeed will return (true, content string)
        /// if case of download failed will return(false, error message)
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

        public static AccessToken GetAccessTokenFromEnv(string envName)
        {
            var tokenString = Environment.GetEnvironmentVariable(envName);
            if (string.IsNullOrEmpty(tokenString))
            {
                throw new Exception("Failed to get the access token from environment variable: " + envName);
            }
            var model = JsonConvert.DeserializeObject<TokenEnvModel>(tokenString);
            if (model == null)
            {
                throw new Exception("Failed to deserialize access token json object: " + tokenString);
            }
            return new AccessToken(model.AccessToken, DateTimeOffset.Parse(model.ExpiresOn));
        }

        [DataContract]
        public class TokenEnvModel
        {
            [DataMember(Name = "accessToken")]
            public string AccessToken { get; set; }
            [DataMember(Name = "expiresOn")]
            public string ExpiresOn { get; set; }
        }
    }
}
