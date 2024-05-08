// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GuestProxyAgentTest.Settings
{
    /// <summary>
    /// Setting class for RunCommand
    /// </summary>
    public class RunCommandSetting
    {
        internal string runCommandName = null!;
        internal string runCommandScriptSAS = null!;
        internal Dictionary<string, string> runCommandParameters = new Dictionary<string, string>();
        /// <summary>
        /// run command will write std output to this blob
        /// </summary>
        internal string outputBlobSAS = null!;
        /// <summary>
        /// run command will write std error output to this blob
        /// </summary>
        internal string errorBlobSAS = null!;
        /// <summary>
        /// if this one is not null or empty, it will
        /// be covert to base64 and passed to run command as an input paramter with name <see cref="GuestProxyAgentTest.Utilities.Constants.RUNCOMMAND_CUSTOM_OUTPUT_SAS_PARAMETER_NAME"/>
        /// the run command script can write customized infomation to this blob, .i.e. agent instance view
        /// </summary>
        internal string customOutputSAS = null!;
        internal TestScenarioSetting testCaseSetting = null!;
    }
}
