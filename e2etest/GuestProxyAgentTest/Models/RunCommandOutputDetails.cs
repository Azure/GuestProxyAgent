// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GuestProxyAgentTest.Models
{
    /// <summary>
    /// RunCommand Output details
    /// </summary>
    public class RunCommandOutputDetails
    {
        /// <summary>
        /// Std output sas url for the run command execution.
        /// </summary>
        public string StdOut { get; set; } = null!;
        /// <summary>
        /// Std error output sas url for the run command execution.
        /// </summary>
        public string StdErr { get; set; } = null!;
        /// <summary>
        /// Customized output url for the run command execution.
        /// </summary>
        public string CustomOut { get; set; } = null!;
        /// <summary>
        /// Indicate if the run command execution status is succeed or not.
        /// </summary>
        public bool Succeed { get; set; }
    }
}
