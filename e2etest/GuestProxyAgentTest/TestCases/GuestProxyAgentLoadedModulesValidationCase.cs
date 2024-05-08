// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using GuestProxyAgentTest.Extensions;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestScenarios;
using GuestProxyAgentTest.Utilities;
using Newtonsoft.Json;

namespace GuestProxyAgentTest.TestCases
{
    public class GuestProxyAgentLoadedModulesValidationCase : TestCaseBase
    {
        public GuestProxyAgentLoadedModulesValidationCase() : base("GuestProxyAgentLoadedModulesValidationCase")
        {
        }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            var baseLineModulesFilePath = Path.Combine(TestSetting.Instance.resourcesFolder, "GuestProxyAgentLoadedModulesBaseline.txt");
            var baseLineModulesSas = StorageHelper.Instance.Upload2SharedBlob(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, baseLineModulesFilePath, context.ScenarioSetting.TestScenarioStroageFolderPrefix);

            context.TestResultDetails = (await RunScriptViaRunCommandV2Async(context, "GuestProxyAgentLoadedModulesValidation.ps1", new List<(string, string)> 
            {
                ("loadedModulesBaseLineSAS", System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(baseLineModulesSas)))
            })).ToTestResultDetails(ConsoleLog);

            if (context.TestResultDetails.Succeed && context.TestResultDetails.CustomOut != null)
            {
                var validationDetails = context.TestResultDetails.SafeDeserializedCustomOutAs<LoadedModulesValidationDetails>();
                // if the validation result is match or no new added modules, then consider the case as succeed.
                if (validationDetails != null
                    && (validationDetails.IsMatch || validationDetails.NewAddedModules == null || validationDetails.NewAddedModules.Count == 0))
                    
                {
                    context.TestResultDetails.Succeed = true;
                }
                else
                {
                    context.TestResultDetails.Succeed = false;
                }
            }
        }
    }

    class LoadedModulesValidationDetails
    {
        public List<string> MissedInBaselineModules { get; set; } = new List<string>();

        public List<string> NewAddedModules { get; set; } = new List<string>();

        public bool IsMatch { get; set; }
    }
}
