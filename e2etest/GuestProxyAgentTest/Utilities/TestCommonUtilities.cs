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
                throw new Exception("Failed to deserialze access token json object: " + tokenString);
            }
            return new AccessToken(model.AccessToken, DateTimeOffset.Parse(model.ExpiresOn));
        }

        /*  public static AccessToken GetAccessTokenFromEnv(string envName)
          {
              var tokenString = "";
              if (envName.Equals("GuestProxyAgentE2EAccessToken"))
              {
                  tokenString = "{\r\n  \"accessToken\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaWF0IjoxNzE5ODYwNTAwLCJuYmYiOjE3MTk4NjA1MDAsImV4cCI6MTcxOTg2NjE4NywiX2NsYWltX25hbWVzIjp7Imdyb3VwcyI6InNyYzEifSwiX2NsYWltX3NvdXJjZXMiOnsic3JjMSI6eyJlbmRwb2ludCI6Imh0dHBzOi8vZ3JhcGgud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3VzZXJzLzQ0Njk2ZTk1LTk2MzctNDcyOC05ZjYzLWE1NDM0MjE2MWIxYy9nZXRNZW1iZXJPYmplY3RzIn19LCJhY3IiOiIxIiwiYWlvIjoiQVZRQXEvOFhBQUFBZ2t3WVoxeEx1WVVHMVF1cU1sUHE0d0FWNEtLQWRCSy92TjVPWW93Qmx0Y3htejVVaFdyU3RnRllncWxVdnZwUU5sRE15WXAxTnh0TUQ3Nllrdjl0R1lJNGZrandranlSbmxQSmNZcE1XZFE9IiwiYW1yIjpbInB3ZCIsInJzYSIsIm1mYSJdLCJhcHBpZCI6ImI2NzdjMjkwLWNmNGItNGE4ZS1hNjBlLTkxYmE2NTBhNGFiZSIsImFwcGlkYWNyIjoiMCIsImRldmljZWlkIjoiZGJkM2UwMmUtZmNkMi00MjA3LWI4ZjctYjc2NjUzMWM5MmE2IiwiZmFtaWx5X25hbWUiOiJTaGFoIiwiZ2l2ZW5fbmFtZSI6Ik5lZXJhbGkiLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiIxNzIuMjAwLjcwLjEzIiwibmFtZSI6Ik5lZXJhbGkgU2hhaCIsIm9pZCI6IjQ0Njk2ZTk1LTk2MzctNDcyOC05ZjYzLWE1NDM0MjE2MWIxYyIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0yMTI3NTIxMTg0LTE2MDQwMTI5MjAtMTg4NzkyNzUyNy02NDkzMTIwMCIsInB1aWQiOiIxMDAzMjAwMjcyNUIyNDcxIiwicmgiOiIwLkFSb0F2NGo1Y3ZHR3IwR1JxeTE4MEJIYlIwWklmM2tBdXRkUHVrUGF3ZmoyTUJNYUFOby4iLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiJLSXRUQ1dQdlJ5Nkpvd1FNNGdTSTg0T3hkZVVnZnpybzBwSWNFandVSEZVIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidW5pcXVlX25hbWUiOiJuZWVyYWxpc2hhaEBtaWNyb3NvZnQuY29tIiwidXBuIjoibmVlcmFsaXNoYWhAbWljcm9zb2Z0LmNvbSIsInV0aSI6IjZkd1JnUWJSTzBLQmdTZi1EWDFxQUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbImI3OWZiZjRkLTNlZjktNDY4OS04MTQzLTc2YjE5NGU4NTUwOSJdLCJ4bXNfaWRyZWwiOiIxIDE4IiwieG1zX3RjZHQiOjEyODkyNDE1NDd9.Pk-Q-794WJpHkZ9iQtZxyxPWC3x-niBHPNQdu0JYlxpzIf488oQ5I4gCEX6R4sNl8ReU6yMYP8veUzsSbSP02mS1vh9RCsWVh0hVnhgH-BJspd2oowZ_hzRnSpObHol5sqdUnCA8QggCr6pOJwGonOX1US2Q63uz9AlI2vNB6Z7lI2ImHHWupd0WqCKAGX3NC0n498nV4-Sm6vrX37dQb2gRz2Hc3DSMDDQgCCtAYKq9w0wiApQuo6cGhHh6s7D7uMLva_-JDOP2l1HTWkHSTg0wi07162g5--d0yJYPnJvl_7ZCLCzt7om6wSmS4dr67rzwPWc5BeYDOv-HprrsKA\",\r\n  \"expiresOn\": \"2024-07-01 20:36:27.000000\",\r\n  \"expires_on\": 1719866187,\r\n  \"subscription\": \"f21bdc74-62a2-437e-acbb-ecc81bbdee5c\",\r\n  \"tenant\": \"72f988bf-86f1-41af-91ab-2d7cd011db47\",\r\n  \"tokenType\": \"Bearer\"\r\n}";
              }
              else if (envName.Equals("GuestProxyAgentE2EAccessTokenForStorageAccount"))
              {
                  tokenString = "{\r\n  \"accessToken\": \"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyIsImtpZCI6Ik1HTHFqOThWTkxvWGFGZnBKQ0JwZ0I0SmFLcyJ9.eyJhdWQiOiJodHRwczovL3N0b3JhZ2UuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0Ny8iLCJpYXQiOjE3MTk4NjU0NzEsIm5iZiI6MTcxOTg2NTQ3MSwiZXhwIjoxNzE5ODcwMDMwLCJfY2xhaW1fbmFtZXMiOnsiZ3JvdXBzIjoic3JjMSJ9LCJfY2xhaW1fc291cmNlcyI6eyJzcmMxIjp7ImVuZHBvaW50IjoiaHR0cHM6Ly9ncmFwaC53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvdXNlcnMvNDQ2OTZlOTUtOTYzNy00NzI4LTlmNjMtYTU0MzQyMTYxYjFjL2dldE1lbWJlck9iamVjdHMifX0sImFjciI6IjEiLCJhaW8iOiJBVlFBcS84WEFBQUFna3dZWjF4THVZVUcxUXVxTWxQcTR3QVY0S0tBZEJLL3ZONU9Zb3dCbHRjeG16NVVoV3JTdGdGWWdxbFV2dnBRTmxETXlZcDFOeHRNRDc2WWt2OXRHWUk0Zmtqd2tqeVJubFBKY1lwTVdkUT0iLCJhbXIiOlsicHdkIiwicnNhIiwibWZhIl0sImFwcGlkIjoiYjY3N2MyOTAtY2Y0Yi00YThlLWE2MGUtOTFiYTY1MGE0YWJlIiwiYXBwaWRhY3IiOiIwIiwiZGV2aWNlaWQiOiJkYmQzZTAyZS1mY2QyLTQyMDctYjhmNy1iNzY2NTMxYzkyYTYiLCJmYW1pbHlfbmFtZSI6IlNoYWgiLCJnaXZlbl9uYW1lIjoiTmVlcmFsaSIsImlkdHlwIjoidXNlciIsImlwYWRkciI6IjE3Mi4xNzIuMzQuMTE1IiwibmFtZSI6Ik5lZXJhbGkgU2hhaCIsIm9pZCI6IjQ0Njk2ZTk1LTk2MzctNDcyOC05ZjYzLWE1NDM0MjE2MWIxYyIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0yMTI3NTIxMTg0LTE2MDQwMTI5MjAtMTg4NzkyNzUyNy02NDkzMTIwMCIsInB1aWQiOiIxMDAzMjAwMjcyNUIyNDcxIiwicmgiOiIwLkFSb0F2NGo1Y3ZHR3IwR1JxeTE4MEJIYlI0R21CdVRVODZoQ2tMYkNzQ2xKZXZFYUFOby4iLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiIzNmwzUDBhNTZUaGJrSmxuNVFqN2NSVHg5bnZwSm5lZlBjUUVGTWVDaWdJIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidW5pcXVlX25hbWUiOiJuZWVyYWxpc2hhaEBtaWNyb3NvZnQuY29tIiwidXBuIjoibmVlcmFsaXNoYWhAbWljcm9zb2Z0LmNvbSIsInV0aSI6IlgtOFo2dWR0amtDSXBPVHhyRjltQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfaWRyZWwiOiIxIDEyIn0.YMHAsGYwMNVLRTIyYl75XsPOtUww0A4dSIeWIj7-7HdvKeNDpTyHIEJ3j3ehFmhx6DC5ZKGUqT7-4gbLcgGxTAOvuG84V1QBu8JNyqMJjO7iEzlZYay5v8_AoAdrYb_Y_2K-IrAXMaoG1KMF4tqxKiLIaGWORKNvE7inJ7SfA4lTLZTu38XJoUMwD8PfrzrqcWzG8RRLUBa63FYHHf1imfvgNWs_H0KSD_yCvrQhfhLa3kZa4OGJxleEI7fzHKW4H2fOMz0PRQP6ouz0tfQY_Wq_97JNFPnnNVz2n4j4VIs6W0GT_rEgEVsL9rZkDEXR8UXloUyhktF-091uAFX4BA\",\r\n  \"expiresOn\": \"2024-07-01 21:40:30.000000\",\r\n  \"expires_on\": 1719870030,\r\n  \"subscription\": \"f21bdc74-62a2-437e-acbb-ecc81bbdee5c\",\r\n  \"tenant\": \"72f988bf-86f1-41af-91ab-2d7cd011db47\",\r\n  \"tokenType\": \"Bearer\"\r\n}";            
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
          }*/

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
