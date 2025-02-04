// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Settings;
using System.Reflection;
using GuestProxyAgentTest.Models;

namespace GuestProxyAgentTest.Utilities
{
    public static class TestMapReader
    {
        static string TestMapFile(bool test_arm64 = false)
        {
            if (test_arm64)
            {
                if (Constants.IS_WINDOWS())
                {
                    return "Test-Map-Arm64.yml";
                }
                else
                {
                    return "Test-Map-Linux-Arm64.yml";
                }
            }
            else
            {
                if (Constants.IS_WINDOWS())
                {
                    return "Test-Map.yml";
                }
                else
                {
                    return "Test-Map-Linux.yml";
                }
            }
        }

        /// <summary>
        /// Read 'Test-Map.yml' and covert to a TestScenarioSetting list
        /// </summary>
        /// <returns></returns>
        public static List<TestScenarioSetting> ReadFlattenTestScenarioSettingFromTestMap(bool test_arm64 = false)
        {
            var curFolder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
            return YamlUtils.DeserializeYaml<TestMap>(Path.Combine(curFolder, "TestMap", TestMapFile(test_arm64)))
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
