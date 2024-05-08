// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Settings;
using System.Reflection;
using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization;
using GuestProxyAgentTest.Models;

namespace GuestProxyAgentTest.Utilities
{
    public static class TestMapReader
    {
        private static readonly string TestMapFile;
        static TestMapReader()
        {
            if (Constants.IS_WINDOWS())
            {
                TestMapFile = "Test-Map.yml";
            }
            else
            {
                TestMapFile = "Test-Map-Linux.yml";
            }
        }

        /// <summary>
        /// Read 'Test-Map.yml' and covert to a TestScenarioSetting list
        /// </summary>
        /// <returns></returns>
        public static List<TestScenarioSetting> ReadFlattenTestScenarioSettingFromTestMap()
        {
            var curFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
            return YamlUtils.DeserializeYaml<TestMap>(Path.Combine(curFolder, "TestMap", TestMapFile))
               .TestGroupList.Select((x) => YamlUtils.DeserializeYaml<TestGroupDetails>(Path.Combine(curFolder, "TestMap", x.Include)))
               .SelectMany(x => x.Scenarios, (group, ele) => new TestScenarioSetting
               {
                   vmImageOffer = group.VmImageOffer,
                   vmImagePublisher = group.VmImagePublisher,
                   vmImageSku = group.VmImageSku,
                   vmImageVersion = group.VmImageVersion,
                   testGroupName = group.GroupName,
                   testScenarioClassName = ele.ClassName,
                   testScenarioName = ele.Name,
               }).ToList();
        }


    }
}
