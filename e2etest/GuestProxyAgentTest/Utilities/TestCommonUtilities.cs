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
        public static void TestSetup(string guestProxyAgentZipFilePath, string testConfigFilePath, string testResultFolder)
        {
            TestSetting.Init(YamlUtils.DeserializeYaml<TestConfig>(testConfigFilePath), guestProxyAgentZipFilePath, testResultFolder);
            StorageHelper.Init(TestSetting.Instance.tenantId, TestSetting.Instance.appClientId);
            VMHelper.Init(TestSetting.Instance.tenantId, TestSetting.Instance.appClientId, TestSetting.Instance.subscriptionId);

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

       /* public static AccessToken GetAccessTokenFromEnv(string envName)
        {
            var tokenString = Environment.GetEnvironmentVariable(envName);
            if (string.IsNullOrEmpty(tokenString))
            {
                throw new Exception("Failed to get the access token from environment variable: " + envName);
            }
            var model = JsonConvert.DeserializeObject<TokenEnvModel>(tokenString);
            if (model == null)
            {
                throw new Exception("Failed to deserialze access token json object: " + tokenString);
            }
            return new AccessToken(model.AccessToken, DateTimeOffset.Parse(model.ExpiresOn));
        }*/

        public static AccessToken GetAccessTokenFromEnv(string envName)
        {
            var tokenString = "";
            if (envName.Equals("GuestProxyAgentE2EAccessToken"))
            {
                tokenString = "{\r\n  \"accessToken\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaWF0IjoxNzE5MzUwNDU0LCJuYmYiOjE3MTkzNTA0NTQsImV4cCI6MTcxOTM1NTYzNCwiX2NsYWltX25hbWVzIjp7Imdyb3VwcyI6InNyYzEifSwiX2NsYWltX3NvdXJjZXMiOnsic3JjMSI6eyJlbmRwb2ludCI6Imh0dHBzOi8vZ3JhcGgud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3VzZXJzLzQ0Njk2ZTk1LTk2MzctNDcyOC05ZjYzLWE1NDM0MjE2MWIxYy9nZXRNZW1iZXJPYmplY3RzIn19LCJhY3IiOiIxIiwiYWlvIjoiQVpRQWEvOFhBQUFBbVRoUG03VC9LN0c1WUVwRWNraEVlTWRBSTlCZDBDalRkN1RhZmJ3RXpDZXlvZjVnRE54TXpBZFU0c2w3aE11YUtwam1uUTJTNHhiNGNtNEcwaFIycjYrU1M0TUQ0WWxKR0xOS045RmR0UjZYWjNMb3pKdDc0Mk8wdk9mdG4xV2tlS2VVUVhQR1hUdjhDbjRzcW1GeWdWYUxkSSsrcHJRNmFJUk9EMzAyYWdTdnA0OWZycS9udVhIcVNqMHd4T1NaIiwiYW1yIjpbInJzYSIsIm1mYSJdLCJhcHBpZCI6ImI2NzdjMjkwLWNmNGItNGE4ZS1hNjBlLTkxYmE2NTBhNGFiZSIsImFwcGlkYWNyIjoiMCIsImRldmljZWlkIjoiZGJkM2UwMmUtZmNkMi00MjA3LWI4ZjctYjc2NjUzMWM5MmE2IiwiZmFtaWx5X25hbWUiOiJTaGFoIiwiZ2l2ZW5fbmFtZSI6Ik5lZXJhbGkiLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiIxNzIuMjAwLjcwLjM1IiwibmFtZSI6Ik5lZXJhbGkgU2hhaCIsIm9pZCI6IjQ0Njk2ZTk1LTk2MzctNDcyOC05ZjYzLWE1NDM0MjE2MWIxYyIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0yMTI3NTIxMTg0LTE2MDQwMTI5MjAtMTg4NzkyNzUyNy02NDkzMTIwMCIsInB1aWQiOiIxMDAzMjAwMjcyNUIyNDcxIiwicmgiOiIwLkFRRUF2NGo1Y3ZHR3IwR1JxeTE4MEJIYlIwWklmM2tBdXRkUHVrUGF3ZmoyTUJNYUFOby4iLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiJLSXRUQ1dQdlJ5Nkpvd1FNNGdTSTg0T3hkZVVnZnpybzBwSWNFandVSEZVIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidW5pcXVlX25hbWUiOiJuZWVyYWxpc2hhaEBtaWNyb3NvZnQuY29tIiwidXBuIjoibmVlcmFsaXNoYWhAbWljcm9zb2Z0LmNvbSIsInV0aSI6Ikw4NWQ2eUhaTVVHZTc0d3hpVGJRQUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbImI3OWZiZjRkLTNlZjktNDY4OS04MTQzLTc2YjE5NGU4NTUwOSJdLCJ4bXNfaWRyZWwiOiIxIDQiLCJ4bXNfdGNkdCI6MTI4OTI0MTU0N30.hOOck4LoKRirH1eAVPqyln1egds8sG1h2zl08BYgfpkXOB_HKOVT9levUZiNXmARwS5NxZg4WWx4lNomn9RLr-FKb3WhF8a3Nl7e-R-kxB2g65HX63ven8SfHQVGdbUmkKdSkRLfxJFtPuoHK4nGrvZmiwJy7HoKJ9OXm5rm5aGN0Rc6hfueV2lYdfAe-AgyR64IQU0Ur1E9aqmDeOdqZwndslG5y_evvAFPExqtBMKcN8TF9E-3O3m_0HvEC8QR9EWn1buxT2lGsoKEAN5u9qUD8sz0diGTYNpvkdT2mcc9Vud9geJuFglW5KIWTSTp3Iw8Ojz3imhuWgf-xUpeHg\",\r\n  \"expiresOn\": \"2024-06-25 22:47:14.000000\",\r\n  \"expires_on\": 1719355634,\r\n  \"subscription\": \"f21bdc74-62a2-437e-acbb-ecc81bbdee5c\",\r\n  \"tenant\": \"72f988bf-86f1-41af-91ab-2d7cd011db47\",\r\n  \"tokenType\": \"Bearer\"\r\n}";
            }
            else if (envName.Equals("GuestProxyAgentE2EAccessTokenForStorageAccount"))
            {
                tokenString = "{\r\n  \"accessToken\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJodHRwczovL3N0b3JhZ2UuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0Ny8iLCJpYXQiOjE3MTkzNTE4OTEsIm5iZiI6MTcxOTM1MTg5MSwiZXhwIjoxNzE5MzU3MzM3LCJfY2xhaW1fbmFtZXMiOnsiZ3JvdXBzIjoic3JjMSJ9LCJfY2xhaW1fc291cmNlcyI6eyJzcmMxIjp7ImVuZHBvaW50IjoiaHR0cHM6Ly9ncmFwaC53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvdXNlcnMvNDQ2OTZlOTUtOTYzNy00NzI4LTlmNjMtYTU0MzQyMTYxYjFjL2dldE1lbWJlck9iamVjdHMifX0sImFjciI6IjEiLCJhaW8iOiJBWlFBYS84WEFBQUF4TWwrZ2VCUUQrMkFrazNkTm45anRkSWhvbXRpOFQ5WlZSYndFZmNKMHVpL0lvNEYrcTd5OXlpZ0JSQm1lUWgwVzJ3aEFPS3MrVndKaW1lSktIWGo1NlVqMFVsVjBodS9MYlRuOCszQ1pFdUVtSTNzNHB2S2pWTTdUWTRxaEJ3blluS0FiMmZTbUxtODZCMmF5d25jZWdHbi9pd1FrbnJMYmtjL1JDMGs2bUxFaWlYVnFJMVlUcVAvb0dTOVYyZGMiLCJhbXIiOlsicnNhIiwibWZhIl0sImFwcGlkIjoiYjY3N2MyOTAtY2Y0Yi00YThlLWE2MGUtOTFiYTY1MGE0YWJlIiwiYXBwaWRhY3IiOiIwIiwiZGV2aWNlaWQiOiJkYmQzZTAyZS1mY2QyLTQyMDctYjhmNy1iNzY2NTMxYzkyYTYiLCJmYW1pbHlfbmFtZSI6IlNoYWgiLCJnaXZlbl9uYW1lIjoiTmVlcmFsaSIsImlkdHlwIjoidXNlciIsImlwYWRkciI6IjE3Mi4xNzIuMzQuMTE1IiwibmFtZSI6Ik5lZXJhbGkgU2hhaCIsIm9pZCI6IjQ0Njk2ZTk1LTk2MzctNDcyOC05ZjYzLWE1NDM0MjE2MWIxYyIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0yMTI3NTIxMTg0LTE2MDQwMTI5MjAtMTg4NzkyNzUyNy02NDkzMTIwMCIsInB1aWQiOiIxMDAzMjAwMjcyNUIyNDcxIiwicmgiOiIwLkFRRUF2NGo1Y3ZHR3IwR1JxeTE4MEJIYlI0R21CdVRVODZoQ2tMYkNzQ2xKZXZFYUFOby4iLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiIzNmwzUDBhNTZUaGJrSmxuNVFqN2NSVHg5bnZwSm5lZlBjUUVGTWVDaWdJIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidW5pcXVlX25hbWUiOiJuZWVyYWxpc2hhaEBtaWNyb3NvZnQuY29tIiwidXBuIjoibmVlcmFsaXNoYWhAbWljcm9zb2Z0LmNvbSIsInV0aSI6ImZCN2pZRjdRaWtxT2JBVENwQkhEQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfaWRyZWwiOiIxIDMwIn0.GRU8bSSalQ4ZEaGmAqJGlwoMWrDJbjB1g95wAO1wfLamI7UWQlAVgq1u33vZFUbbhvynnTnNGmPSCNmS8ZNv4yO_5uEccyT8VxcNOUxj1-vNVaTcJHEK22wE27DGCoNEv0bcsclgUYWqjjJnNo126zMoysXCXs0Q5MhmdShltp11ZGLm_4v826wY-HRIsGJ77dM-uUgQKZRVCbc1IWakJKn_bw3Ywe8ot0uUCH5Fvb_Eow5SCTCtduRBeHKs-OKdD994BWcN9lVJW2YO__Zs_DUcOhKwcUIq9yGxwHI1jsNUrrOyBZ9d39DlJo9gsoct2HCPZOp13RcCk5vqPgYbfw\",\r\n  \"expiresOn\": \"2024-06-25 23:15:37.000000\",\r\n  \"expires_on\": 1719357337,\r\n  \"subscription\": \"f21bdc74-62a2-437e-acbb-ecc81bbdee5c\",\r\n  \"tenant\": \"72f988bf-86f1-41af-91ab-2d7cd011db47\",\r\n  \"tokenType\": \"Bearer\"\r\n}";
            }
            if (string.IsNullOrEmpty(tokenString))
            {
                throw new Exception("Failed to get the access token from environment variable: " + envName);
            }
            var model = JsonConvert.DeserializeObject<TokenEnvModel>(tokenString);
            if (model == null)
            {
                throw new Exception("Failed to deserialze access token json object: " + tokenString);
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
