// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Azure.ResourceManager.Resources;
using GuestProxyAgentTest.Settings;
using System.Security.Cryptography.X509Certificates;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// VMHelper class that will be used to VM operations
    /// </summary>
    internal class VMHelper
    {
        private static VMHelper _instance = null!;
        private ArmClient client = null!;
        
        private VMHelper() { }

        /// <summary>
        /// Single instance of VMHelper, needs to call Init before using
        /// </summary>
        public static VMHelper Instance
        {
            get
            {
                if(null == _instance)
                {
                    throw new Exception("not init.");
                }
                return _instance;
            }
        }

        /// <summary>
        /// Init the VMHelper, need to be called before using VMHelper.Instance
        /// </summary>
        /// <param name="tenantId">azure tenant id</param>
        /// <param name="appClientId">application principal id</param>
        /// <param name="defaultSubId">default subscription id, the resources will be created on the default subscription</param>
        /// <param name="cert">certificate that will be used to retrieve the application principal</param>
        public static void Init(string tenantId, string appClientId, string defaultSubId, X509Certificate2? cert)
        {
            if(null != _instance)
            {
                return;
            }
            _instance = new VMHelper();
            _instance.client = new ArmClient(new ClientCertificateCredential(tenantId, appClientId, cert), defaultSubId);
        }

        /// <summary>
        /// Get VirtualMachineResource of the VM, specified by resource group name and virtual machine name
        /// </summary>
        /// <param name="rgName">resource group name</param>
        /// <param name="vmName">virtual machine name</param>
        /// <returns></returns>
        public VirtualMachineResource GetVMResource(string rgName, string vmName)
        {
            var sub = client.GetDefaultSubscription();
            return sub.GetResourceGroups().Get(rgName).Value.GetVirtualMachine(vmName);
        }

        /// <summary>
        /// Clean up the test related Azure resources, including resource group and saved azure blob storage,during the test.
        /// </summary>
        /// <param name="testCaseSetting">test case setting, that contains the information of the resources that needs to be cleaned up</param>
        public void CleanupTestResources(TestScenarioSetting testCaseSetting)
        {
            var sub = client.GetDefaultSubscription();
            var rgs = sub.GetResourceGroups();
            if(rgs.Exists(testCaseSetting.ResourceGroupName))
            {
                rgs.Get(testCaseSetting.ResourceGroupName).Value.Delete(Azure.WaitUntil.Completed);
            }

            StorageHelper.Instance.CleanSharedBlobFolder(Constants.SHARED_E2E_TEST_OUTPUT_CONTAINER_NAME, testCaseSetting.TestScenarioStroageFolderPrefix);
            StorageHelper.Instance.CleanSharedBlobFolder(Constants.SHARED_MSI_CONTAINER_NAME, testCaseSetting.TestScenarioStroageFolderPrefix);
        }

        public async Task CleanupOldTestResourcesAndForget()
        {
            var sub = await client.GetDefaultSubscriptionAsync();
            
            var rgs = sub.GetResourceGroups().Where(rg =>
                rg.Data.Tags.ContainsKey(Constants.COULD_CLEANUP_TAG_NAME)
                && rg.Data.Tags[Constants.COULD_CLEANUP_TAG_NAME].Equals("true", StringComparison.OrdinalIgnoreCase)
            );

            foreach (var rg in rgs)
            {                
                var firstDeployment = rg.GetArmDeployments().Where(x => x?.Data?.Properties?.Timestamp != null).OrderBy(x => x.Data.Properties.Timestamp).FirstOrDefault();
                if(firstDeployment != null && firstDeployment?.Data?.Properties?.Timestamp?.DateTime.AddDays(2) <= DateTime.UtcNow)
                {
                    await rg.DeleteAsync(Azure.WaitUntil.Started);
                }
            }
        }
        
    }
}
