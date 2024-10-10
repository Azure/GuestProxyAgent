// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Utilities;
using Newtonsoft.Json;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace GuestProxyAgentTest.Settings
{
    /// <summary>
    /// E2ETestSetting related azure resource
    /// </summary>
    public class TestSetting
    {
        private static TestSetting _instance = null!;
        public static TestSetting Instance
        {
            get
            {
                return _instance;
            }
        }

        internal string tenantId = "";
        internal string appClientId = "";
        internal string certThumbprint = "";
        internal string subscriptionId = "";
        internal AzureLocation location = AzureLocation.WestUS;
        internal string vmSize = "Standard_B4as_v2";
        internal string scriptsFolder = null!;
        internal string resourcesFolder = null!;
        internal string zipFilePath = null!;
        internal string sharedStorageAccountUrl = null!;
        internal string testResultFolder = null!;
        internal int testTimeoutMilliseconds = 1000 * 60 * 120;
        internal string windowsInVmWireServerAccessControlProfileReferenceId = null!;
        internal string windowsInVmIMDSAccessControlProfileReferenceId = null!;
        internal string linuxInVmWireServerAccessControlProfileReferenceId = null!;
        internal string linuxInVmIMDSAccessControlProfileReferenceId = null!;


        private TestSetting() { }

        public static void Init(TestConfig testConfig, string zipFilePath, string testResultFolder)
        {
            var scriptsFolder = Constants.IS_WINDOWS() ? "Scripts" : "LinuxScripts";


            if (_instance != null)
            {
                return;
            }
            _instance = new TestSetting()
            {
                tenantId = testConfig.TenantId,
                appClientId = testConfig.AppClientId,
                location = new AzureLocation(testConfig.Location),
                subscriptionId = testConfig.SubscriptionId,
                vmSize = testConfig.VmSize,
                scriptsFolder = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, scriptsFolder),
                resourcesFolder = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "Resources"),
                sharedStorageAccountUrl = testConfig.SharedStorageAccountUrl,
                windowsInVmWireServerAccessControlProfileReferenceId = testConfig.WindowsInVmWireServerAccessControlProfileReferenceId,
                windowsInVmIMDSAccessControlProfileReferenceId = testConfig.WindowsInVmIMDSAccessControlProfileReferenceId,
                linuxInVmWireServerAccessControlProfileReferenceId = testConfig.LinuxInVmWireServerAccessControlProfileReferenceId,
                linuxInVmIMDSAccessControlProfileReferenceId = testConfig.LinuxInVmIMDSAccessControlProfileReferenceId,
                zipFilePath = zipFilePath,
                testResultFolder = testResultFolder,
            };
        }
    }

    public class GuestProxyAgentE2ETokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return TestCommonUtilities.GetAccessTokenFromEnv(Constants.GUEST_PROXY_AGENT_E2E_ACCESS_TOKEN_ENV);
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(GetToken(requestContext, cancellationToken));
        }


    }

    public class GuestProxyAgentE2EStorageAccountTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return TestCommonUtilities.GetAccessTokenFromEnv(Constants.GUEST_PROXY_AGENT_E2E_ACCESS_TOKEN_STORAGE_ACCOUNT_ENV);
        }

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(GetToken(requestContext, cancellationToken));
        }
    }
}
