// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace GuestProxyAgentTest.Utilities
{
    /// <summary>
    /// Utility for certificate operations
    /// </summary>
    public static class CertificateUtility
    {
        /// <summary>
        /// check if the certificate was installed
        /// </summary>
        /// <param name="storeName">store name of the cert</param>
        /// <param name="storeLocation">store location of the cert</param>
        /// <param name="thumbPrint">thumb print of the cert</param>
        /// <returns></returns>
        public static bool IsCertInstalled(StoreName storeName, StoreLocation storeLocation, string thumbPrint)
        {
            string normalizedThumbPrint = thumbPrint.Replace(" ", "").ToUpper();
            var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            var findResult = store.Certificates.Find(X509FindType.FindByThumbprint, normalizedThumbPrint, false);
            store.Close();
            var found = findResult.Count >= 1;
            return found;
        }

        /// <summary>
        /// Get certificate by the thumbprint
        /// </summary>
        /// <param name="thumbPrint"></param>
        /// <param name="storeName"></param>
        /// <param name="storeLocation"></param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificate(string thumbPrint, StoreName storeName, StoreLocation storeLocation)
        {
            X509Store store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint, false);
                if (certs.Count <= 0)
                {
                    return null;
                }
                else
                {
                    return certs[0];
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("GetCerficiate error: " + e.Message);
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }

            return null;
        }

        /// <summary>
        /// Get certificate with check private key access
        /// </summary>
        /// <param name="thumbPrint"></param>
        /// <param name="storeName"></param>
        /// <param name="requirePrivateKeyAccess"></param>
        /// <returns></returns>
        public static X509Certificate2? GetCertificate(string thumbPrint, StoreName storeName, bool requirePrivateKeyAccess = false)
        {
            Console.WriteLine("getting cert with thumbprint: " + thumbPrint);
            var cert = GetCertificate(thumbPrint, storeName, StoreLocation.CurrentUser);
            if (cert != null)
            {
                Console.WriteLine("Found cert on current user, " + cert.Thumbprint);
            }
            if (cert != null && (!requirePrivateKeyAccess || CanAccessPrivateKey(cert)))
            {
                return cert;
            }

            cert = GetCertificate(thumbPrint, storeName, StoreLocation.LocalMachine);
            if (cert != null)
            {
                Console.WriteLine("Found cert on local machine, " + cert.Thumbprint);
            }
            return (cert != null && !(requirePrivateKeyAccess && !CanAccessPrivateKey(cert))) ? cert : null;
        }

        /// <summary>
        /// Get certificate with check private key access
        /// </summary>
        /// <param name="certNameInKV"></param>
        /// <param name="requirePrivateKeyAccess"></param>
        /// <returns></returns>
        public static X509Certificate2? GetCertificate(string certNameInKV, bool requirePrivateKeyAccess = false)
        {
            Console.WriteLine("Getting cert with name in KeyVault: " + certNameInKV);
            var based64EncodedCert = Environment.GetEnvironmentVariable(certNameInKV);
            if (string.IsNullOrEmpty(based64EncodedCert))
            {
                Console.WriteLine("No cert found in environment variable: " + certNameInKV);
                return null;
            }
            var cert = new X509Certificate2(Convert.FromBase64String(based64EncodedCert));            
            if (cert != null)
            {
                Console.WriteLine("Found cert on from enviornment variable, " + cert.Thumbprint);
            }

            return (cert != null && !(requirePrivateKeyAccess && !CanAccessPrivateKey(cert))) ? cert : null;
        }

        private static bool CanAccessPrivateKey(X509Certificate2 cert)
        {
            if (null == cert)
            {
                return false;
            }

            try
            {
                Console.WriteLine("check cert private key, has private key: " + cert.HasPrivateKey);
                //a. Has private key doesn't mean we can access the private key (check by null != cert.PrivateKey)
                //b. PrivateKey can be get doesn't mean the information inside didn't corrupt already (check by cert.PrivateKey.KeySize > 0)
                return cert.HasPrivateKey
                       && null != cert.PrivateKey
                       && cert.PrivateKey.KeySize > 0;
            }
            catch (CryptographicException ex)
            {
                //no permission to access the certificate or privary key
                Console.WriteLine("check cert private key error: " + ex.Message);
                return false;
            }
        }
    }
}
