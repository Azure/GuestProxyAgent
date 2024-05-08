// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Utilities;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace GuestProxyAgentTest.Settings
{
    /// <summary>
    /// E2ETestSetting related azure resource
    /// </summary>
    class TestSetting
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
        internal X509Certificate2? cert = null;
        internal string subscriptionId = "";
        internal AzureLocation location = AzureLocation.WestUS;
        internal string vmSize = "Standard_B4as_v2";
        internal string scriptsFolder = null!;
        internal string resourcesFolder = null!;
        internal string zipFilePath = null!;
        internal string sharedStorageAccountUrl = null!;
        internal string testResultFolder = null!;
        internal int testTimeoutMilliseconds = 1000 * 60 * 120;

        private TestSetting() { }

        /// <summary>
        /// Init the E2ETest setting instance
        /// </summary>
        /// <param name="tenantId"></param>
        /// <param name="appClientId"></param>
        /// <param name="cert"></param>
        /// <param name="subscriptionId"></param>
        /// <param name="location"></param>
        /// <param name="scriptsFolder"></param>
        /// <param name="zipFilePath"></param>
        /// <param name="testResultFolder"></param>
        public static void Init(string tenantId, string appClientId, X509Certificate2? cert, string subscriptionId, AzureLocation location, string vmSize, string sharedStorageAccountUrl, string scriptsFolder, string resourcesFolder, string zipFilePath, string testResultFolder)
        {
            if (_instance != null)
            {
                return;
            }
            _instance = new TestSetting();
            _instance.tenantId = tenantId;
            _instance.appClientId = appClientId;
            _instance.location = location;
            _instance.subscriptionId = subscriptionId;
            _instance.vmSize = vmSize;
            _instance.cert = cert;
            _instance.zipFilePath = zipFilePath;
            _instance.scriptsFolder = scriptsFolder;
            _instance.resourcesFolder = resourcesFolder;
            _instance.sharedStorageAccountUrl = sharedStorageAccountUrl;
            _instance.testResultFolder = testResultFolder;
        }

        public static void Init(TestConfig testConfig, string zipFilePath, string testResultFolder)
        {
            var cert = CertificateUtility.GetCertificate(testConfig.CertNameInKV, true);
            if (cert == null)
            {
                cert = CertificateUtility.GetCertificate(testConfig.CertThumbprint, StoreName.My, false);
            }
            var scriptsFolder = Constants.IS_WINDOWS() ? "Scripts" : "LinuxScripts";
            Init(testConfig.TenantId
                , testConfig.AppClientId
                , cert
                , testConfig.SubscriptionId
                , new AzureLocation(testConfig.Location)
                , testConfig.VmSize
                , testConfig.SharedStorageAccountUrl
                , Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, scriptsFolder)
                , Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "Resources")
                , zipFilePath
                , testResultFolder);
        }
    }
}
