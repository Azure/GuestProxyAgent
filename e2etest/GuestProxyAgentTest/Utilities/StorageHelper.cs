// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using Azure.Core;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Specialized;
using Azure.Storage.Sas;
using GuestProxyAgentTest.Settings;
using System.Security.Cryptography.X509Certificates;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// Helper class for operation shared storage account 'e2etestsharedstorage'
    /// </summary>
    internal class StorageHelper
    {
        private static StorageHelper _instance = null!;
        private TokenCredential tokenCredential = null!;

        private StorageHelper() { }

        /// <summary>
        /// Init of the StorageHelper Instance
        /// </summary>
        /// <param name="tenantId">azure tenant id</param>
        /// <param name="appClientId">application id of the app principal</param>
        /// <param name="cert">certificate that will be used to retrieved the app principal</param>
        public static void Init(string tenantId, string appClientId)
        {
            if(_instance != null) return;
            _instance = new StorageHelper();
            _instance.tokenCredential = new GuestProxyAgentE2EStorageAccountTokenCredential();
        }

        /// <summary>
        /// Instance of StroageHelper, need to call Init before using
        /// The storageHelper will operate the pre-created storage account 'e2etestsharedstorage'
        /// </summary>
        public static StorageHelper Instance
        {
            get
            {
                if(null == _instance)
                {
                    throw new Exception("");
                }
                return _instance; 
            }
        }

        /// <summary>
        /// Create an append blob in the shared blob
        /// </summary>
        /// <param name="containerName">blob container name</param>
        /// <param name="fileName">file name</param>
        /// <param name="parentPathInBlob">parent folder path in the blob</param>
        /// <returns></returns>
        public string CreateAppendBlob(string containerName, string fileName, string parentPathInBlob = null!)
        {
            var containerClient = new BlobContainerClient(new Uri($"{TestSetting.Instance.sharedStorageAccountUrl}/{containerName}"), this.tokenCredential);

            if (null != parentPathInBlob)
            {
                fileName = $"{parentPathInBlob}/{fileName}";
            }
            containerClient.GetAppendBlobClient(fileName).CreateIfNotExists();
            return GenerateSasUriFromSharedBlob(containerName, fileName);
        }

        /// <summary>
        /// Upload to local file to the shared blob, will use the local file name on the blob file name
        /// </summary>
        /// <param name="containerName">container name</param>
        /// <param name="filePath">local file path(full path)</param>
        /// <param name="parentPathInBlob">parent folder name in the blob</param>
        /// <returns></returns>
        public string Upload2SharedBlob(string containerName, string filePath, string parentPathInBlob = null!)
        {
            return Upload2SharedBlob(containerName, filePath, Path.GetFileName(filePath), parentPathInBlob);
            
        }

        /// <summary>
        /// Upload to local file to shared blob with specified file name on the blob file name
        /// </summary>
        /// <param name="containerName">container name</param>
        /// <param name="filePath">local file path (full path)</param>
        /// <param name="fileName">file name that will be used as the blob file name</param>
        /// <param name="parentPathInBlob">parent folder path in the blob</param>
        /// <returns></returns>
        public string Upload2SharedBlob(string containerName, string filePath, string fileName, string parentPathInBlob = null!)
        {
            var containerClient = new BlobContainerClient(new Uri($"{TestSetting.Instance.sharedStorageAccountUrl}/{containerName}"), this.tokenCredential);

            if (null != parentPathInBlob)
            {
                fileName = $"{parentPathInBlob}/{fileName}";
            }
            containerClient.GetBlobClient(fileName).Upload(filePath, true);
            return GenerateSasUriFromSharedBlob(containerName, fileName);
        }

        /// <summary>
        /// Generate the SaS URI for a blob on shared repo
        /// </summary>
        /// <param name="containerName">container name</param>
        /// <param name="fileName">file name including the parent path of the blob</param>
        /// <returns></returns>
        public string GenerateSasUriFromSharedBlob(string containerName, string fileName)
        {
            return DoGenerateSasUri(TestSetting.Instance.sharedStorageAccountUrl, containerName, fileName);
        }

        /// <summary>
        /// Clean/delete all the folder under a folder of the shared blob
        /// </summary>
        /// <param name="containerName">container name</param>
        /// <param name="folderPath">folder path in the blob</param>
        public void CleanSharedBlobFolder(string containerName, string folderPath)
        {
            var serviceClient = new BlobServiceClient(new Uri(TestSetting.Instance.sharedStorageAccountUrl), this.tokenCredential);
            var containerClient = serviceClient.GetBlobContainerClient(containerName);
            foreach(var blob in containerClient.GetBlobs(prefix: folderPath))
            {
                containerClient.GetBlobClient(blob.Name).DeleteIfExists();
            }
        }

        private string DoGenerateSasUri(string storageAccountUrl, string containerName, string fileName)
        {
            var bsClient = new BlobServiceClient(new Uri(storageAccountUrl), this.tokenCredential);
            Azure.Storage.Blobs.Models.UserDelegationKey userDelegationKey =
                     bsClient.GetUserDelegationKey(DateTimeOffset.UtcNow.AddMinutes(-20),
                                                          DateTimeOffset.UtcNow.AddDays(1));
            // Create a SAS token that's valid for one hour.
            BlobSasBuilder sasBuilder = new BlobSasBuilder()
            {
                BlobContainerName = containerName,
                Resource = "c"
            };


            sasBuilder.ExpiresOn = DateTimeOffset.UtcNow.AddDays(7);
            sasBuilder.SetPermissions(BlobContainerSasPermissions.All);

            BlobUriBuilder blobUriBuilder = new BlobUriBuilder(new Uri($"{storageAccountUrl}/{containerName}/{fileName}"))
            {
                Sas = sasBuilder.ToSasQueryParameters(userDelegationKey,
                                          bsClient.AccountName)
            };
            return blobUriBuilder.ToUri().ToString();
        }
    


    }
}
