using Azure.ResourceManager.Compute.Models;
using GuestProxyAgentTest.Models;
using GuestProxyAgentTest.Settings;
using GuestProxyAgentTest.TestScenarios;
using Newtonsoft.Json;

namespace GuestProxyAgentTest.TestCases
{
    internal class EnableProxyAgentCase : TestCaseBase
    {
        public EnableProxyAgentCase() : this("EnableProxyAgentCase", true)
        { }
        public EnableProxyAgentCase(string testCaseName) : this(testCaseName, true)
        { }

        public EnableProxyAgentCase(string testCaseName, bool enableProxyAgent) : base(testCaseName)
        {
            EnableProxyAgent = enableProxyAgent;
        }

        internal bool EnableProxyAgent { get; set; }

        public override async Task StartAsync(TestCaseExecutionContext context)
        {
            var vmr = context.VirtualMachineResource;

            var patch = new VirtualMachinePatch()
            {
                SecurityProfile = new SecurityProfile
                {
                    ProxyAgentSettings = new ProxyAgentSettings
                    {
                        Enabled = EnableProxyAgent
                    }
                }
            };

            if (EnableProxyAgent)
            {
                patch.SecurityProfile.ProxyAgentSettings.WireServer = new HostEndpointSettings
                {
                    InVmAccessControlProfileReferenceId = TestSetting.Instance.InVmWireServerAccessControlProfileReferenceId
                };
                patch.SecurityProfile.ProxyAgentSettings.Imds = new HostEndpointSettings
                {
                    InVmAccessControlProfileReferenceId = TestSetting.Instance.InVmIMDSAccessControlProfileReferenceId
                };
            }

            await vmr.UpdateAsync(Azure.WaitUntil.Completed, patch);
            var iv = await vmr.InstanceViewAsync();
            context.TestResultDetails = new TestCaseResultDetails
            {
                CustomOut = JsonConvert.SerializeObject(iv),
                StdOut = "Enable ProxyAgent succeed.",
                StdErr = "",
                Succeed = true,
                FromBlob = false,
            };

        }

    }
}
