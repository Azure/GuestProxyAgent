// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
namespace GuestProxyAgentTest.Settings
{
    /// <summary>
    /// Setting for a test case, including test group name, case name, vmImage Type, etc
    /// </summary>
    public class TestScenarioSetting
    {
        internal string testGroupName = "";
        internal string testScenarioName = "BVTScenario";
        internal string vmImagePublisher = "";
        internal string vmImageOffer = "";
        internal string vmImageSku = "";
        internal string vmImageVersion = "";
        internal string suffixName = new Random().Next(1000).ToString();
        internal string testScenarioClassName = "GuestProxyAgentTest.TestScenarios.BVTScenario";
        internal int testScenarioTimeoutMillseconds = 1000 * 60 * 60;
        

        internal VMImageDetails VMImageDetails
        {
            get
            {
                return new VMImageDetails
                {
                    Publisher = vmImagePublisher,
                    Offer = vmImageOffer,
                    Sku = vmImageSku,
                    Version = vmImageVersion
                };
            }
        }

        public string ResourceGroupName
        {
            get
            {
                return this.testGroupName + "_" + this.testScenarioName + suffixName;
            }
        }

        public string TestScenarioStroageFolderPrefix
        {
            get
            {
                return ResourceGroupName;
            }
        }
    }

    public class VMImageDetails
    {
        public string Publisher { get; set; } = null!;
        public string Offer { get; set; } = null!;
        public string Sku { get; set; } = null!;
        public string Version { get; set; } = null!;
    }
}
