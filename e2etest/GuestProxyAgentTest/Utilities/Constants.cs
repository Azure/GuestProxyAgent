// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using Azure.ResourceManager.Network.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// Constants used in the project
    /// </summary>
    public static class Constants
    {
        public static readonly string SHARED_SCRIPTS_CONTAINER_NAME = "scripts";
        public static readonly string SHARED_MSI_CONTAINER_NAME = "guestproxyagentmsis";
        public static readonly string SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME = "e2etestoutputs";
        public static readonly string RUNCOMMAND_OUTPUT_FILE_NAME = "runCommandOutput.txt";
        public static readonly string RUNCOMMAND_ERROR_OUTPUT_FILE_NAME = "runCommandErr.txt";
        public static readonly string RUNCOMMAND_CUSTOM_OUTPUT_SAS_PARAMETER_NAME = "customOutputJsonSAS";
        public static readonly string COULD_CLEANUP_TAG_NAME = "CouldCleanup";
        public const string INSTALL_LINUX_GUEST_PROXY_AGENT_PACKAGE_SCRIPT_NAME = "InstallGuestProxyAgentPackage.sh";
        public static readonly string GUEST_PROXY_AGENT_E2E_ACCESS_TOKEN_ENV = "GuestProxyAgentE2EAccessToken";
        public static readonly string GUEST_PROXY_AGENT_E2E_ACCESS_TOKEN_STORAGE_ACCOUNT_ENV = "GuestProxyAgentE2EAccessTokenForStorageAccount";

        public static readonly string INSTALL_GUEST_PROXY_AGENT_SCRIPT_NAME;
        public static readonly string COLLECT_INVM_GA_LOG_SCRIPT_NAME;
        public static readonly string GUEST_PROXY_AGENT_VALIDATION_SCRIPT_NAME;
        public static readonly string IMDS_PING_TEST_SCRIPT_NAME;
        public static readonly string SETUP_CGROUP2_SCRIPT_NAME;
        public static readonly string GUEST_PROXY_AGENT_EXTENSION_VALIDATION_SCRIPT_NAME;
        public static readonly string INSTALL_GUEST_PROXY_AGENT_EXTENSION_SCRIPT_NAME;
        static Constants()
        {
            if (IS_WINDOWS())
            {
                INSTALL_GUEST_PROXY_AGENT_SCRIPT_NAME = "InstallGuestProxyAgent.ps1";
                COLLECT_INVM_GA_LOG_SCRIPT_NAME = "CollectInVMGALog.ps1";
                GUEST_PROXY_AGENT_VALIDATION_SCRIPT_NAME = "GuestProxyAgentValidation.ps1";
                IMDS_PING_TEST_SCRIPT_NAME = "IMDSPingTest.ps1";
                GUEST_PROXY_AGENT_EXTENSION_VALIDATION_SCRIPT_NAME = "GuestProxyAgentExtensionValidation.ps1";
                INSTALL_GUEST_PROXY_AGENT_EXTENSION_SCRIPT_NAME = "InstallGuestProxyAgentExtension.ps1";
            }
            else
            {
                INSTALL_GUEST_PROXY_AGENT_SCRIPT_NAME = "InstallGuestProxyAgent.sh";
                COLLECT_INVM_GA_LOG_SCRIPT_NAME = "CollectInVMGALog.sh";
                GUEST_PROXY_AGENT_VALIDATION_SCRIPT_NAME = "GuestProxyAgentValidation.sh";
                IMDS_PING_TEST_SCRIPT_NAME = "IMDSPingTest.sh";
                SETUP_CGROUP2_SCRIPT_NAME = "SetupCGroup2.sh";
                GUEST_PROXY_AGENT_EXTENSION_VALIDATION_SCRIPT_NAME = "GuestProxyAgentExtensionValidation.sh";
                INSTALL_GUEST_PROXY_AGENT_EXTENSION_SCRIPT_NAME = "InstallGuestProxyAgentExtension.sh";
            }
        }

        public static bool IS_WINDOWS()
        {
           return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }
    }
}
