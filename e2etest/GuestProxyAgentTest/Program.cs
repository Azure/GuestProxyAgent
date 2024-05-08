// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Utilities;

namespace GuestProxyAgentTest
{

    /// <summary>
    /// Entry point program class
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Entry point main method
        /// </summary>
        /// <param name="args">
        /// args[0]: test config file yml file path
        /// args[1]: test result folder path, the test pipeline will publish the test result under this folder
        /// args[2]: guest proxy agent msi file path
        /// </param>
        static async Task Main(string[] args)
        {
            var testConfigFilePath = args[0];
            var testResultFolder = args[1];
            var guestProxyAgentZipFilePath = args[2];

            TestCommonUtilities.TestSetup(guestProxyAgentZipFilePath, testConfigFilePath, testResultFolder);

            VMHelper.Instance.CleanupOldTestResourcesAndForget();

            await new GuestProxyAgentScenarioTests().StartAsync(TestMapReader.ReadFlattenTestScenarioSettingFromTestMap());
            Console.WriteLine("E2E Test run completed.");
        }
    }
}