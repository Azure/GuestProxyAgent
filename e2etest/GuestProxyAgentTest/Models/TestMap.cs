// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
namespace GuestProxyAgentTest.Models
{
    public class TestMap
    {
        public List<TestGroupConfig> TestGroupList { get; set; } = null!;
    }

    public class TestGroupConfig
    {
        public string Include { get; set; } = null!;
    }

    public class TestGroupDetails
    {
        public string GroupName { get; set; } = null!;
        public string VmImagePublisher { get; set; } = null!;
        public string VmImageOffer { get; set; } = null!;
        public string VmImageSku { get; set; } = null!;
        public string VmImageVersion { get; set; } = null!;
        public List<TestScenarioConfig> Scenarios { get; set; } = null!;
    }

    public class TestScenarioConfig
    {
        public string Name { get; set; } = null!;
        public string ClassName { get; set; } = null!;
    }
}
