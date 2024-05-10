// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using GuestProxyAgentTest.Settings;
using System;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// Builder class for build RunCommandSetting
    /// </summary>
    public class RunCommandSettingBuilder
    {
        internal string scriptFullPath = null!;
        private TestScenarioSetting _testCaseSetting = null!;
        private RunCommandSetting runCommandSetting;

        public RunCommandSettingBuilder()
        {
            this.runCommandSetting = new RunCommandSetting();
        }

        /// <summary>
        /// Specifiy test case setting for the run command setting
        /// </summary>
        /// <param name="testCaseSetting"></param>
        /// <returns></returns>
        public RunCommandSettingBuilder TestScenarioSetting(TestScenarioSetting testCaseSetting)
        {
            this._testCaseSetting = testCaseSetting;
            return this;
        }

        /// <summary>
        /// Set run command name
        /// </summary>
        /// <param name="runCommandName"></param>
        /// <returns></returns>
        public RunCommandSettingBuilder RunCommandName(string runCommandName)
        {
            this.runCommandSetting.runCommandName = runCommandName;
            return this;
        }

        /// <summary>
        /// Set run command script by local file
        /// The 'scriptFullPath' is the full path of a local script file that will be uploaded to blob and used as the run command script rul
        /// </summary>
        /// <param name="scriptFullPath"></param>
        /// <returns></returns>
        public RunCommandSettingBuilder ScriptFullPath(string scriptFullPath)
        {
            this.scriptFullPath = scriptFullPath;
            return this;
        }

        /// <summary>
        /// Set custom output SAS url
        /// </summary>
        /// <param name="customOutputSas"></param>
        /// <returns></returns>
        public RunCommandSettingBuilder CustomOutputSas(string customOutputSas)
        {
            this.runCommandSetting.customOutputSAS = customOutputSas;
            return this;
        }

        /// <summary>
        /// Add paramter for the run command script.
        /// </summary>
        /// <param name="paramName"></param>
        /// <param name="paramValue"></param>
        /// <returns></returns>
        public RunCommandSettingBuilder AddParameter(string paramName, string paramValue)
        {
            this.runCommandSetting.runCommandParameters.Add(paramName, paramValue);
            return this;
        }

        public RunCommandSettingBuilder AddParameters(List<(string, string)> list)
        {
            if(list == null || list.Count == 0)
            {
                return this;
            }
            foreach(var kv in list)
            {
                this.runCommandSetting.runCommandParameters.Add(kv.Item1, kv.Item2);
            }
            return this;
        }
        /// <summary>
        /// Set run command script by blob SAS url
        /// </summary>
        /// <param name="scriptSAS"></param>
        /// <returns></returns>
        public RunCommandSettingBuilder RunCommandScriptSAS(string scriptSAS)
        {
            this.runCommandSetting.runCommandScriptSAS = scriptSAS;
            return this;
        }

        /// <summary>
        /// Build the run command setting
        /// Setup run command script, if non of scriptFullPath or runCommandScriptSAS was specified, will throw the paramter error exception
        /// if both was set, the runCommandScriptSAS has more priority.
        /// Setup testcasesetting/output/erroutput for the run command
        /// </summary>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public RunCommandSetting Build()
        {
            if(this.runCommandSetting.runCommandScriptSAS == null && this.scriptFullPath == null) 
            {
                throw new Exception("neither specifying the run command script from runCommandScriptSAS nor scriptFullPath");
            }

            if(this.runCommandSetting.runCommandName == null)
            {
                throw new Exception("runCommandName was not specified.");
            }

            if(this.runCommandSetting.runCommandScriptSAS == null)
            {
                this.runCommandSetting.runCommandScriptSAS = StorageHelper.Instance.Upload2SharedBlob(Constants.SHARED_SCRIPTS_CONTAINER_NAME, this.scriptFullPath);
            }
            
            runCommandSetting.testCaseSetting = _testCaseSetting;
            this.runCommandSetting.outputBlobSAS = StorageHelper.Instance.CreateAppendBlob(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, Constants.RUNCOMMAND_OUTPUT_FILE_NAME, this._testCaseSetting.TestScenarioStroageFolderPrefix + "/" + this.runCommandSetting.runCommandName);
            this.runCommandSetting.errorBlobSAS= StorageHelper.Instance.CreateAppendBlob(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, Constants.RUNCOMMAND_ERROR_OUTPUT_FILE_NAME, this._testCaseSetting.TestScenarioStroageFolderPrefix + "/" + this.runCommandSetting.runCommandName);

            if(this.runCommandSetting.customOutputSAS != null && this.runCommandSetting.customOutputSAS.Count() > 0) 
            {
                this.runCommandSetting.runCommandParameters.Add(Constants.RUNCOMMAND_CUSTOM_OUTPUT_SAS_PARAMETER_NAME, System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(this.runCommandSetting.customOutputSAS)));
            }
            
            return this.runCommandSetting;
        }
    }
}
