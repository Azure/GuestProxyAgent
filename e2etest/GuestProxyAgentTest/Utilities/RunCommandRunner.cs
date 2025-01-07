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
        /// <param name="vmr">virtual machine resource, used to specify the azure virtual machine instance</param>
        /// <param name="runCommandSettingBuilder">builder for run command setting</param>
        /// <param name="runCommandParameterSetter">parameter setter for the run command script</param>
        /// <returns></returns>
        public static async Task<RunCommandOutputDetails> ExecuteRunCommandOnVM(VirtualMachineResource vmr
            , RunCommandSettingBuilder runCommandSettingBuilder
            , Func<RunCommandSettingBuilder, RunCommandSettingBuilder> runCommandParameterSetter = null!)
        {
            var vmrcs = vmr.GetVirtualMachineRunCommands();
            Console.WriteLine("Creating runcommand on vm.");

            if (null != runCommandParameterSetter)
            {
                runCommandSettingBuilder = runCommandParameterSetter(runCommandSettingBuilder);
            }

            var runCommandSetting = runCommandSettingBuilder.Build();

            int retryCnt = 0;

            while(retryCnt < 3)
            {
                try
                {
                    await vmrcs.CreateOrUpdateAsync(WaitUntil.Completed, runCommandSetting.runCommandName, toVMRunCommandData(runCommandSetting));

                    var iv = vmrcs.Get(runCommandSetting.runCommandName, "InstanceView").Value.Data.InstanceView;

                    if (iv.ExitCode != 0 || iv.ExecutionState != ExecutionState.Succeeded)
                    {
                        Console.WriteLine(string.Format("RunCommand {0} failed with exit code {1} and ExecutionState {2}, Execution Message {3} , has retried {4}.", runCommandSetting.runCommandName, iv.ExitCode, iv.ExecutionState.ToString(), iv.ExecutionMessage, retryCnt));
                        Thread.Sleep(15 * 1000);
                        retryCnt++;
                        continue;
                    }
                    return new RunCommandOutputDetails
                    {
                        StdOut = runCommandSetting.outputBlobSAS,
                        StdErr = runCommandSetting.errorBlobSAS,
                        CustomOut = runCommandSetting.customOutputSAS,
                        Succeed = true,
                    };
                }
                catch (Exception ex)
                {
                    Console.WriteLine(string.Format("RunCommand {0} failed with exception: {1}, has retried {2}.", runCommandSetting.runCommandName, ex, retryCnt));
                    Thread.Sleep(15 * 1000);
                    retryCnt++;
                    continue;
                }
            }
            
            return new RunCommandOutputDetails
            {
                StdOut = runCommandSetting.outputBlobSAS,
                StdErr = runCommandSetting.errorBlobSAS,
                CustomOut = runCommandSetting.customOutputSAS,
                Succeed = false,
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
