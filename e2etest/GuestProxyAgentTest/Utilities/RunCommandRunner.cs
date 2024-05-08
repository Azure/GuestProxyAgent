// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Compute.Models;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// Helper class for Running 'RunCommand' on a particular virtual machine
    /// </summary>
    public class RunCommandRunner
    {
        /// <summary>
        /// Execute/Run a 'RunCommand' on a particular virtual machine
        /// </summary>
        /// <param name="vmr">virtual machine resource, used to specify the azure virutal mahcine instance</param>
        /// <param name="runCommandSettingBuilder">builder for run command setting</param>
        /// <param name="runCommandParameterSetter">paramter setter for the run command script</param>
        /// <returns></returns>
        public static async Task<RunCommandOutputDetails> ExecuteRunCommandOnVM(VirtualMachineResource vmr
            , RunCommandSettingBuilder runCommandSettingBuilder
            , Func<RunCommandSettingBuilder, RunCommandSettingBuilder> runCommandParameterSetter = null!)
        {
            var vmrcs = vmr.GetVirtualMachineRunCommands();
            Console.WriteLine("Creating runcommand on vm.");

            if(null != runCommandParameterSetter)
            {
                runCommandSettingBuilder = runCommandParameterSetter(runCommandSettingBuilder);
            }

            var runCommandSetting = runCommandSettingBuilder.Build();

            await vmrcs.CreateOrUpdateAsync(WaitUntil.Completed, runCommandSetting.runCommandName, toVMRunCommandData(runCommandSetting));
            
            var iv = vmrcs.Get(runCommandSetting.runCommandName, "InstanceView").Value.Data.InstanceView;
            return new RunCommandOutputDetails
            {
                StdOut = runCommandSetting.outputBlobSAS,
                StdErr = runCommandSetting.errorBlobSAS,
                CustomOut = runCommandSetting.customOutputSAS,
                Succeed = iv.ExecutionState == ExecutionState.Succeeded && iv.ExitCode == 0,
            };
        }

        private static VirtualMachineRunCommandData toVMRunCommandData(RunCommandSetting runCommandSetting)
        {
            var res = new VirtualMachineRunCommandData(TestSetting.Instance.location)
            {
                Source = new VirtualMachineRunCommandScriptSource()
                {
                    ScriptUri = new Uri(runCommandSetting.runCommandScriptSAS),
                },
                AsyncExecution = false,
                TimeoutInSeconds = 3600,
                OutputBlobUri = new Uri(runCommandSetting.outputBlobSAS),
                ErrorBlobUri = new Uri(runCommandSetting.errorBlobSAS),
            };
            foreach(var x in runCommandSetting.runCommandParameters.Select(kv => new RunCommandInputParameter(kv.Key, kv.Value)))
            {
                res.Parameters.Add(x);
            }
            return res;
        }
    }

    
};
